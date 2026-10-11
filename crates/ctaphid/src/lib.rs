//! CTAPHID message framing from the CTAP 2.1 specification, section 11.2.
//!
//! Pure state machine, no I/O. Feed 64-byte output reports from the host to
//! [`Server::handle_report`] and send the packets in [`Action::Send`] back as
//! input reports. CTAPHID_CBOR requests surface as [`Action::Process`]; answer
//! them with [`Server::response`]. Time is passed in (`now_ms`, any monotonic
//! millisecond clock) so timeouts are deterministic.
//!
//! `no_std` + `alloc`; the `std` feature only adds `std::error::Error` impls.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// Size of every HID report (full-speed USB HID).
pub const REPORT_SIZE: usize = 64;
/// Payload bytes in an initialization packet: 64 - CID(4) - CMD(1) - BCNT(2).
pub const INIT_DATA_SIZE: usize = REPORT_SIZE - 7;
/// Payload bytes in a continuation packet: 64 - CID(4) - SEQ(1).
pub const CONT_DATA_SIZE: usize = REPORT_SIZE - 5;
/// Highest continuation sequence number (7 bits).
pub const MAX_SEQ: u8 = 0x7f;
/// Largest message: one init packet plus 128 continuation packets (7609).
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + (MAX_SEQ as usize + 1) * CONT_DATA_SIZE;
/// Broadcast channel, only valid for CTAPHID_INIT.
pub const BROADCAST_CID: u32 = 0xffff_ffff;
/// CTAPHID protocol version reported by INIT.
pub const PROTOCOL_VERSION: u8 = 2;
/// Bit set in the command byte of initialization packets.
pub const TYPE_INIT: u8 = 0x80;

pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
/// Device does not implement CTAPHID_MSG (CTAP1/U2F).
pub const CAPABILITY_NMSG: u8 = 0x08;

/// One HID report.
pub type Packet = [u8; REPORT_SIZE];

/// CTAPHID commands, without the init bit.
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

/// CTAPHID_ERROR codes.
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

impl ErrorCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => ErrorCode::InvalidCmd,
            0x02 => ErrorCode::InvalidPar,
            0x03 => ErrorCode::InvalidLen,
            0x04 => ErrorCode::InvalidSeq,
            0x05 => ErrorCode::MsgTimeout,
            0x06 => ErrorCode::ChannelBusy,
            0x0a => ErrorCode::LockRequired,
            0x0b => ErrorCode::InvalidChannel,
            0x7f => ErrorCode::Other,
            _ => return None,
        })
    }
}

/// KEEPALIVE status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    Processing = 1,
    UpNeeded = 2,
}

/// Static configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub device_version: (u8, u8, u8),
    pub capabilities: u8,
    /// Maximum gap between packets of one message before it is dropped with
    /// ERR_MSG_TIMEOUT. The spec leaves the value to the implementation.
    pub continuation_timeout_ms: u64,
    /// Maximum allocated channels; the oldest is dropped when exceeded.
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
    None,
    /// Send these packets to the host, in order.
    Send(Vec<Packet>),
    /// Complete request for the application. The device is busy until
    /// [`Server::response`] or [`Server::abort`].
    Process {
        cid: u32,
        cmd: Command,
        payload: Arc<[u8]>,
    },
    /// Host cancelled the request in progress on `cid`. CANCEL gets no reply;
    /// the application should finish with CTAP2_ERR_KEEPALIVE_CANCEL.
    Cancel {
        cid: u32,
    },
    /// WINK: send the packets; the caller may also signal the user.
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

/// Error from [`fragment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLong(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLong(n) => write!(f, "message of {n} bytes exceeds CTAPHID maximum"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameError {}

/// Split a message into an init packet and continuation packets.
pub fn fragment(cid: u32, cmd: Command, payload: &[u8]) -> Result<Vec<Packet>, FrameError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(FrameError::TooLong(payload.len()));
    }
    let mut out = Vec::with_capacity(
        1 + payload
            .len()
            .saturating_sub(INIT_DATA_SIZE)
            .div_ceil(CONT_DATA_SIZE),
    );
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
        c[4] = seq as u8; // < 128, bounded by the size check
        c[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(c);
    }
    Ok(out)
}

fn single(cid: u32, cmd: Command, byte: u8) -> Packet {
    let mut p = [0u8; REPORT_SIZE];
    p[0..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = TYPE_INIT | cmd as u8;
    p[6] = 1;
    p[7] = byte;
    p
}

/// One CTAPHID_ERROR packet.
pub fn error_packet(cid: u32, code: ErrorCode) -> Packet {
    single(cid, Command::Error, code as u8)
}

/// One CTAPHID_KEEPALIVE packet.
pub fn keepalive_packet(cid: u32, status: KeepaliveStatus) -> Packet {
    single(cid, Command::Keepalive, status as u8)
}

fn empty_reply(cid: u32, cmd: Command) -> Vec<Packet> {
    let mut p = [0u8; REPORT_SIZE];
    p[0..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = TYPE_INIT | cmd as u8;
    alloc::vec![p]
}

fn send1(p: Packet) -> Action {
    Action::Send(alloc::vec![p])
}

/// Device side of CTAPHID.
#[derive(Debug)]
pub struct Server {
    config: Config,
    channels: VecDeque<u32>,
    next_cid: u32,
    assembly: Option<Assembly>,
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

    /// Channel waiting for an application response, if any.
    pub fn busy_channel(&self) -> Option<u32> {
        self.busy
    }

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

    /// Expire stale partial messages and locks. Call periodically.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Packet> {
        let mut out = Vec::new();
        if let Some(a) = &self.assembly {
            if now_ms.saturating_sub(a.last_ms) > self.config.continuation_timeout_ms {
                out.push(error_packet(a.cid, ErrorCode::MsgTimeout));
                self.assembly = None;
            }
        }
        if self.lock.is_some_and(|l| now_ms >= l.until_ms) {
            self.lock = None;
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

    /// Drop the in-progress request without replying.
    pub fn abort(&mut self, cid: u32) {
        if self.busy == Some(cid) {
            self.busy = None;
        }
    }

    /// Feed one output report from the host.
    pub fn handle_report(&mut self, report: &[u8], now_ms: u64) -> Action {
        let mut pending = self.poll(now_ms);
        let action = self.handle_inner(report, now_ms);
        if pending.is_empty() {
            return action;
        }
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
            // A new request wins over reporting a stale timeout; the stale
            // host will time out on its own.
            other => other,
        }
    }

    fn handle_inner(&mut self, report: &[u8], now_ms: u64) -> Action {
        if report.len() != REPORT_SIZE {
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
        // INIT is always accepted: it is how hosts resynchronise.
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
            return send1(error_packet(cid, ErrorCode::ChannelBusy));
        }
        if let Some(a) = &self.assembly {
            if a.cid != cid {
                return send1(error_packet(cid, ErrorCode::ChannelBusy));
            }
            // Init packet while continuations are owed: abort the message.
            self.assembly = None;
            return send1(error_packet(cid, ErrorCode::InvalidSeq));
        }
        if self.lock.is_some_and(|l| l.cid != cid) {
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
            return Action::None; // spurious continuation: ignored
        };
        if a.cid != cid {
            return send1(error_packet(cid, ErrorCode::ChannelBusy));
        }
        if seq != a.next_seq {
            self.assembly = None;
            return send1(error_packet(cid, ErrorCode::InvalidSeq));
        }
        let take = (a.total - a.data.len()).min(CONT_DATA_SIZE);
        a.data.extend_from_slice(&report[5..5 + take]);
        a.last_ms = now_ms;
        a.next_seq = a.next_seq.wrapping_add(1);
        if a.data.len() < a.total {
            return Action::None;
        }
        match self.assembly.take() {
            Some(a) => self.dispatch(a.cid, a.cmd, a.data, now_ms),
            None => Action::None,
        }
    }

    fn handle_init(&mut self, cid: u32, report: &[u8], bcnt: usize) -> Action {
        if bcnt != 8 {
            return send1(error_packet(cid, ErrorCode::InvalidLen));
        }
        if cid != BROADCAST_CID && !self.is_allocated(cid) {
            return send1(error_packet(cid, ErrorCode::InvalidChannel));
        }
        let new_cid = if cid == BROADCAST_CID {
            self.allocate_cid()
        } else {
            // Resync: abandon anything in progress here, keep the CID.
            if self.assembly.as_ref().is_some_and(|a| a.cid == cid) {
                self.assembly = None;
            }
            if self.busy == Some(cid) {
                self.busy = None;
            }
            cid
        };
        let (maj, min, build) = self.config.device_version;
        let mut p = [0u8; REPORT_SIZE];
        p[0..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = TYPE_INIT | Command::Init as u8;
        p[6] = 17;
        p[7..15].copy_from_slice(&report[7..15]);
        p[15..19].copy_from_slice(&new_cid.to_be_bytes());
        p[19] = PROTOCOL_VERSION;
        p[20] = maj;
        p[21] = min;
        p[22] = build;
        p[23] = self.config.capabilities;
        send1(p)
    }

    fn dispatch(&mut self, cid: u32, cmd: Command, payload: Vec<u8>, now_ms: u64) -> Action {
        match cmd {
            Command::Ping => match fragment(cid, Command::Ping, &payload) {
                Ok(p) => Action::Send(p),
                Err(_) => send1(error_packet(cid, ErrorCode::InvalidLen)),
            },
            Command::Wink => {
                if self.config.capabilities & CAPABILITY_WINK == 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                Action::Wink(empty_reply(cid, Command::Wink))
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
                Action::Send(empty_reply(cid, Command::Lock))
            }
            Command::Cbor => {
                if self.config.capabilities & CAPABILITY_CBOR == 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                if payload.is_empty() {
                    return send1(error_packet(cid, ErrorCode::InvalidLen));
                }
                self.busy = Some(cid);
                Action::Process {
                    cid,
                    cmd,
                    payload: Arc::from(payload),
                }
            }
            Command::Msg => {
                if self.config.capabilities & CAPABILITY_NMSG != 0 {
                    return send1(error_packet(cid, ErrorCode::InvalidCmd));
                }
                self.busy = Some(cid);
                Action::Process {
                    cid,
                    cmd,
                    payload: Arc::from(payload),
                }
            }
            Command::Init | Command::Cancel | Command::Keepalive | Command::Error => {
                send1(error_packet(cid, ErrorCode::InvalidCmd))
            }
        }
    }
}

/// A complete message (command without the init bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Arc<[u8]>,
}

/// Host side reassembly of device replies, for tools and fixtures.
#[derive(Debug, Default)]
pub struct Reassembler {
    cur: Option<(u32, u8, usize, Vec<u8>, u8)>,
}

impl Reassembler {
    /// Feed a packet; returns the message once complete.
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
                    payload: Arc::from(data),
                }));
            }
            self.cur = Some((cid, cmd, total, data, 0));
            return Ok(None);
        }
        let Some((ccid, _, total, data, seq)) = self.cur.as_mut() else {
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
        if data.len() < *total {
            return Ok(None);
        }
        Ok(self.cur.take().map(|(cid, cmd, _, data, _)| Message {
            cid,
            cmd,
            payload: Arc::from(data),
        }))
    }
}
