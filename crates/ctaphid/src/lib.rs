//! CTAPHID message framing, written from the public CTAP 2.1 specification
//! (section 11.2, "USB Human Interface Device (USB HID)").
//!
//! This crate is a pure state machine. It never touches a device: the caller
//! feeds it 64-byte output reports received from the host
//! ([`Server::handle_report`]) and sends whatever [`Action::Send`] packets it
//! returns as 64-byte input reports. Requests the application must handle
//! (CTAPHID_CBOR) are surfaced as [`Action::Process`]; the application then
//! answers with [`Server::response`].
//!
//! Time is passed in explicitly (`now_ms`, any monotonic millisecond clock), so
//! timeouts are deterministic and testable.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

/// Size of every HID report, in bytes (full-speed USB HID, as the spec assumes).
pub const REPORT_SIZE: usize = 64;
/// Payload bytes that fit in an initialization packet (64 - CID(4) - CMD(1) - BCNT(2)).
pub const INIT_DATA_SIZE: usize = REPORT_SIZE - 7;
/// Payload bytes that fit in a continuation packet (64 - CID(4) - SEQ(1)).
pub const CONT_DATA_SIZE: usize = REPORT_SIZE - 5;
/// Highest continuation sequence number (sequence is 7 bits: 0..=0x7f).
pub const MAX_SEQ: u8 = 0x7f;
/// Largest message expressible with one init packet and 128 continuation packets.
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + (MAX_SEQ as usize + 1) * CONT_DATA_SIZE;
/// Broadcast channel identifier, only valid for CTAPHID_INIT.
pub const BROADCAST_CID: u32 = 0xffff_ffff;
/// CTAPHID protocol version reported in the INIT response.
pub const PROTOCOL_VERSION: u8 = 2;
/// Bit set in the command byte of every initialization packet.
pub const TYPE_INIT: u8 = 0x80;

/// One 64-byte HID report.
pub type Packet = [u8; REPORT_SIZE];

/// CTAPHID commands (values without the 0x80 init bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
}

impl Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Command::Ping,
            0x03 => Command::Msg,
            0x04 => Command::Lock,
            0x06 => Command::Init,
            0x08 => Command::Wink,
            0x10 => Command::Cbor,
            0x11 => Command::Cancel,
            0x3b => Command::Keepalive,
            0x3f => Command::Error,
            _ => return None,
        })
    }
}

/// CTAPHID_ERROR codes (spec 11.2.9.1.6 / 11.2.9.1.7 region).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidCmd = 0x01,
    InvalidPar = 0x02,
    InvalidLen = 0x03,
    InvalidSeq = 0x04,
    MsgTimeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0a,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

/// KEEPALIVE status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    Processing = 1,
    UpNeeded = 2,
}

/// Capability flags reported in the INIT response.
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
/// "No MSG": the device does not implement CTAPHID_MSG (CTAP1/U2F).
pub const CAPABILITY_NMSG: u8 = 0x08;

/// Static configuration of the HID server.
#[derive(Debug, Clone)]
pub struct Config {
    pub device_version: (u8, u8, u8),
    pub capabilities: u8,
    /// Maximum time between two packets of the same message before the
    /// partial message is discarded with ERR_MSG_TIMEOUT. The spec leaves the
    /// exact value to the implementation; 500-3000 ms is typical.
    pub continuation_timeout_ms: u64,
    /// Maximum number of simultaneously allocated channels. When exceeded the
    /// least recently allocated channel is dropped.
    pub max_channels: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_version: (0, 1, 0),
            capabilities: CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG,
            continuation_timeout_ms: 1000,
            max_channels: 64,
        }
    }
}

/// What the caller must do after feeding a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing to send.
    None,
    /// Send these packets to the host, in order.
    Send(Vec<Packet>),
    /// A complete request the application must handle. The channel is now
    /// busy until [`Server::response`] (or [`Server::abort`]) is called.
    Process {
        cid: u32,
        cmd: Command,
        payload: Vec<u8>,
    },
    /// The host cancelled the request in progress on `cid`. No reply is due
    /// for CANCEL itself; the application should finish the pending request
    /// with CTAP2_ERR_KEEPALIVE_CANCEL.
    Cancel { cid: u32 },
    /// The host asked the device to identify itself (WINK). The packets are
    /// the reply to send; the caller may additionally blink/notify.
    Wink(Vec<Packet>),
}

#[derive(Debug, Clone)]
struct Assembly {
    cid: u32,
    cmd: Command,
    total: usize,
    data: Vec<u8>,
    next_seq: u8,
    last_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct LockState {
    cid: u32,
    until_ms: u64,
}

/// Errors from [`Server::response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Payload longer than [`MAX_MESSAGE_SIZE`].
    TooLong(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLong(n) => write!(f, "message of {n} bytes exceeds CTAPHID maximum"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Split a message into CTAPHID packets (init packet + continuation packets).
pub fn fragment(cid: u32, cmd: Command, payload: &[u8]) -> Result<Vec<Packet>, FrameError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(FrameError::TooLong(payload.len()));
    }
    let mut out = Vec::new();
    let mut p = [0u8; REPORT_SIZE];
    p[0..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = TYPE_INIT | cmd as u8;
    p[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(INIT_DATA_SIZE);
    p[7..7 + first].copy_from_slice(&payload[..first]);
    out.push(p);
    for (seq, chunk) in payload[first..].chunks(CONT_DATA_SIZE).enumerate() {
        let mut c = [0u8; REPORT_SIZE];
        c[0..4].copy_from_slice(&cid.to_be_bytes());
        c[4] = seq as u8; // bounded by MAX_MESSAGE_SIZE check above
        c[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(c);
    }
    Ok(out)
}

/// Build a single CTAPHID_ERROR packet.
pub fn error_packet(cid: u32, code: ErrorCode) -> Packet {
    // Cannot fail: one byte payload.
    fragment(cid, Command::Error, &[code as u8]).expect("1-byte payload")[0]
}

/// Build a single CTAPHID_KEEPALIVE packet.
pub fn keepalive_packet(cid: u32, status: KeepaliveStatus) -> Packet {
    fragment(cid, Command::Keepalive, &[status as u8]).expect("1-byte payload")[0]
}

/// The device side of CTAPHID.
#[derive(Debug)]
pub struct Server {
    config: Config,
    channels: VecDeque<u32>,
    next_cid: u32,
    assembly: Option<Assembly>,
    /// Channel whose request is being processed by the application.
    busy: Option<u32>,
    lock: Option<LockState>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Server {
            config,
            channels: VecDeque::new(),
            next_cid: 1,
            assembly: None,
            busy: None,
            lock: None,
        }
    }

    /// Channel currently waiting for an application response, if any.
    pub fn busy_channel(&self) -> Option<u32> {
        self.busy
    }

    /// True if `cid` was allocated by CTAPHID_INIT and is still live.
    pub fn is_allocated(&self, cid: u32) -> bool {
        self.channels.contains(&cid)
    }

    fn allocate_cid(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if cid == 0 || cid == BROADCAST_CID || self.channels.contains(&cid) {
                continue;
            }
            if self.channels.len() >= self.config.max_channels {
                if let Some(old) = self.channels.pop_front() {
                    self.drop_channel_state(old);
                }
            }
            self.channels.push_back(cid);
            return cid;
        }
    }

    fn drop_channel_state(&mut self, cid: u32) {
        if self.assembly.as_ref().is_some_and(|a| a.cid == cid) {
            self.assembly = None;
        }
        if self.busy == Some(cid) {
            self.busy = None;
        }
        if self.lock.is_some_and(|l| l.cid == cid) {
            self.lock = None;
        }
    }

    /// Expire timed-out partial messages and locks. Call periodically (e.g.
    /// every 100 ms) and send any returned packets.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Packet> {
        let mut out = Vec::new();
        if let Some(a) = &self.assembly {
            if now_ms.saturating_sub(a.last_ms) > self.config.continuation_timeout_ms {
                out.push(error_packet(a.cid, ErrorCode::MsgTimeout));
                self.assembly = None;
            }
        }
        if let Some(l) = self.lock {
            if now_ms >= l.until_ms {
                self.lock = None;
            }
        }
        out
    }

    /// Finish the request in progress on `cid` and get the reply packets.
    pub fn response(
        &mut self,
        cid: u32,
        cmd: Command,
        payload: &[u8],
    ) -> Result<Vec<Packet>, FrameError> {
        if self.busy == Some(cid) {
            self.busy = None;
        }
        fragment(cid, cmd, payload)
    }

    /// Drop the in-progress request without sending anything.
    pub fn abort(&mut self, cid: u32) {
        if self.busy == Some(cid) {
            self.busy = None;
        }
    }

    fn locked_out(&self, cid: u32) -> bool {
        self.lock.is_some_and(|l| l.cid != cid)
    }

    /// Feed one 64-byte output report from the host.
    pub fn handle_report(&mut self, report: &[u8], now_ms: u64) -> Action {
        let mut pending = self.poll(now_ms);
        let action = self.handle_inner(report, now_ms);
        if pending.is_empty() {
            return action;
        }
        // Timeout errors were generated; prepend them when we can.
        match action {
            Action::None => Action::Send(pending),
            Action::Send(p) => {
                pending.extend(p);
                Action::Send(pending)
            }
            Action::Wink(p) => {
                pending.extend(p);
                Action::Wink(pending)
            }
            // Timeouts concern a different (stale) message; delivering the
            // new request is more important. The stale host gets nothing,
            // which it will treat as its own timeout.
            other => other,
        }
    }

    fn handle_inner(&mut self, report: &[u8], now_ms: u64) -> Action {
        if report.len() != REPORT_SIZE {
            // Not a valid report; nothing sensible to reply on.
            return Action::None;
        }
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if cid == 0 {
            return send1(error_packet(cid, ErrorCode::InvalidChannel));
        }
        if report[4] & TYPE_INIT == 0 {
            return self.handle_continuation(cid, report, now_ms);
        }
        let raw_cmd = report[4] & !TYPE_INIT;
        let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;

        // INIT is always accepted (it is how hosts resynchronise).
        if raw_cmd == Command::Init as u8 {
            return self.handle_init(cid, report, bcnt);
        }
        if cid == BROADCAST_CID || !self.is_allocated(cid) {
            return send1(error_packet(cid, ErrorCode::InvalidChannel));
        }
        if raw_cmd == Command::Cancel as u8 {
            if self.busy == Some(cid) {
                return Action::Cancel { cid };
            }
            if self.assembly.as_ref().is_some_and(|a| a.cid == cid) {
                self.assembly = None;
            }
            return Action::None;
        }
        if self.busy.is_some() {
            // While a request is being processed, other requests get
            // ERR_CHANNEL_BUSY (including new requests on the busy channel).
            return send1(error_packet(cid, ErrorCode::ChannelBusy));
        }
        if let Some(a) = &self.assembly {
            if a.cid != cid {
                return send1(error_packet(cid, ErrorCode::ChannelBusy));
            }
            // New init packet on a channel that still owes continuation
            // packets: abort the old message.
            self.assembly = None;
            return send1(error_packet(cid, ErrorCode::InvalidSeq));
        }
        if self.locked_out(cid) {
            return send1(error_packet(cid, ErrorCode::ChannelBusy));
        }
        let Some(cmd) = Command::from_u8(raw_cmd) else {
            return send1(error_packet(cid, ErrorCode::InvalidCmd));
        };
        if bcnt > MAX_MESSAGE_SIZE {
            return send1(error_packet(cid, ErrorCode::InvalidLen));
        }
        let first = bcnt.min(INIT_DATA_SIZE);
        let mut data = Vec::with_capacity(bcnt);
        data.extend_from_slice(&report[7..7 + first]);
        if data.len() == bcnt {
            return self.dispatch(cid, cmd, data, now_ms);
        }
        self.assembly = Some(Assembly {
            cid,
            cmd,
            total: bcnt,
            data,
            next_seq: 0,
            last_ms: now_ms,
        });
        Action::None
    }

    fn handle_continuation(&mut self, cid: u32, report: &[u8], now_ms: u64) -> Action {
        let seq = report[4];
        let Some(a) = self.assembly.as_mut() else {
            // Spurious continuation packets are ignored.
            return Action::None;
        };
        if a.cid != cid {
            // Continuation for another channel while one is assembling: the
            // other host is out of sync; tell it the device is busy.
            return send1(error_packet(cid, ErrorCode::ChannelBusy));
        }
        if seq != a.next_seq {
            self.assembly = None;
            return send1(error_packet(cid, ErrorCode::InvalidSeq));
        }
        let remaining = a.total - a.data.len();
        let take = remaining.min(CONT_DATA_SIZE);
        a.data.extend_from_slice(&report[5..5 + take]);
        a.last_ms = now_ms;
        a.next_seq = a.next_seq.wrapping_add(1);
        if a.data.len() < a.total {
            if a.next_seq > MAX_SEQ {
                // Unreachable given the MAX_MESSAGE_SIZE check, kept as a guard.
                self.assembly = None;
                return send1(error_packet(cid, ErrorCode::InvalidSeq));
            }
            return Action::None;
        }
        let a = self.assembly.take().expect("checked above");
        self.dispatch(a.cid, a.cmd, a.data, now_ms)
    }

    fn handle_init(&mut self, cid: u32, report: &[u8], bcnt: usize) -> Action {
        if bcnt != 8 {
            return send1(error_packet(cid, ErrorCode::InvalidLen));
        }
        if cid != BROADCAST_CID && !self.is_allocated(cid) {
            return send1(error_packet(cid, ErrorCode::InvalidChannel));
        }
        let nonce = &report[7..15];
        let new_cid = if cid == BROADCAST_CID {
            self.allocate_cid()
        } else {
            // Resynchronise: abandon anything in progress on this channel and
            // hand back the same CID.
            if self.assembly.as_ref().is_some_and(|a| a.cid == cid) {
                self.assembly = None;
            }
            if self.busy == Some(cid) {
                self.busy = None;
            }
            cid
        };
        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&new_cid.to_be_bytes());
        payload.push(PROTOCOL_VERSION);
        let (maj, min, build) = self.config.device_version;
        payload.extend_from_slice(&[maj, min, build, self.config.capabilities]);
        Action::Send(fragment(cid, Command::Init, &payload).expect("17 bytes"))
    }

    fn dispatch(&mut self, cid: u32, cmd: Command, payload: Vec<u8>, now_ms: u64) -> Action {
        match cmd {
            Command::Ping => Action::Send(fragment(cid, Command::Ping, &payload).expect("bounded")),
            Command::Wink => {
                if self.config.capabilities & CAPABILITY_WINK == 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                Action::Wink(fragment(cid, Command::Wink, &[]).expect("empty"))
            }
            Command::Lock => {
                if payload.len() != 1 || payload[0] > 10 {
                    return send1(error_packet(cid, ErrorCode::InvalidPar));
                }
                let secs = payload[0] as u64;
                self.lock = if secs == 0 {
                    None
                } else {
                    Some(LockState {
                        cid,
                        until_ms: now_ms + secs * 1000,
                    })
                };
                Action::Send(fragment(cid, Command::Lock, &[]).expect("empty"))
            }
            Command::Cbor => {
                if self.config.capabilities & CAPABILITY_CBOR == 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                if payload.is_empty() {
                    return send1(error_packet(cid, ErrorCode::InvalidLen));
                }
                self.busy = Some(cid);
                Action::Process { cid, cmd, payload }
            }
            Command::Msg => {
                if self.config.capabilities & CAPABILITY_NMSG != 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                self.busy = Some(cid);
                Action::Process { cid, cmd, payload }
            }
            // Device-to-host only, or handled earlier.
            Command::Init | Command::Cancel | Command::Keepalive | Command::Error => {
                send1(error_packet(cid, ErrorCode::InvalidCmd))
            }
        }
    }
}

fn send1(p: Packet) -> Action {
    Action::Send(vec![p])
}

/// Host-side reassembly of device replies (useful for tests and tools).
#[derive(Debug, Default)]
pub struct Reassembler {
    cur: Option<(u32, u8, usize, Vec<u8>, u8)>,
}

/// A complete message (command without the init bit, payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Vec<u8>,
}

impl Reassembler {
    /// Feed a packet; returns a message once complete. Errors on protocol
    /// violations (bad sequence, unexpected continuation).
    pub fn push(&mut self, p: &[u8]) -> Result<Option<Message>, &'static str> {
        if p.len() != REPORT_SIZE {
            return Err("bad report size");
        }
        let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        if p[4] & TYPE_INIT != 0 {
            let cmd = p[4] & !TYPE_INIT;
            let total = u16::from_be_bytes([p[5], p[6]]) as usize;
            if total > MAX_MESSAGE_SIZE {
                return Err("length too large");
            }
            let first = total.min(INIT_DATA_SIZE);
            let data = p[7..7 + first].to_vec();
            if data.len() == total {
                self.cur = None;
                return Ok(Some(Message {
                    cid,
                    cmd,
                    payload: data,
                }));
            }
            self.cur = Some((cid, cmd, total, data, 0));
            return Ok(None);
        }
        let Some((ccid, _cmd, total, data, seq)) = self.cur.as_mut() else {
            return Err("unexpected continuation");
        };
        if *ccid != cid {
            return Err("continuation for other channel");
        }
        if p[4] != *seq {
            self.cur = None;
            return Err("bad sequence");
        }
        *seq += 1;
        let take = (*total - data.len()).min(CONT_DATA_SIZE);
        data.extend_from_slice(&p[5..5 + take]);
        if data.len() == *total {
            let (cid, cmd, _, data, _) = self.cur.take().expect("present");
            return Ok(Some(Message {
                cid,
                cmd,
                payload: data,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
