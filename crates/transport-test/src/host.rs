use ctap2::{Authenticator, Backend, Bytes, CredentialStore, UserPresence};
use ctaphid::{fragment, Action, Command, Config, Reassembler, Server, BROADCAST_CID};

/// Packets exchanged for one transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HidStats {
    pub out_packets: usize,
    pub in_packets: usize,
}

/// Host side of an in-memory CTAPHID link.
pub struct Host {
    pub server: Server,
    pub now_ms: u64,
    cid: Option<u32>,
}

impl Default for Host {
    fn default() -> Self {
        Host::new()
    }
}

fn collect(packets: &[ctaphid::Packet]) -> Result<ctaphid::Message, String> {
    let mut r = Reassembler::default();
    let mut msg = None;
    for p in packets {
        msg = r.push(p).map_err(|e| e.to_string())?;
    }
    msg.ok_or_else(|| "incomplete reply".to_string())
}

impl Host {
    pub fn new() -> Self {
        Host {
            server: Server::new(Config::default()),
            now_ms: 0,
            cid: None,
        }
    }

    /// CTAPHID_INIT on the broadcast channel; returns the new channel.
    pub fn connect(&mut self, nonce: [u8; 8]) -> Result<u32, String> {
        let pkts = fragment(BROADCAST_CID, Command::Init, &nonce).map_err(|e| e.to_string())?;
        let Action::Send(reply) = self.server.handle_report(&pkts[0], self.now_ms) else {
            return Err("INIT got no reply".into());
        };
        let m = collect(&reply)?;
        if m.cid != BROADCAST_CID
            || m.cmd != Command::Init as u8
            || m.payload.len() != 17
            || m.payload[..8] != nonce
        {
            return Err(format!("bad INIT reply {m:?}"));
        }
        let cid = u32::from_be_bytes([m.payload[8], m.payload[9], m.payload[10], m.payload[11]]);
        self.cid = Some(cid);
        Ok(cid)
    }

    /// Send one CTAPHID_CBOR request through the framing and return the
    /// authenticator response.
    pub fn transact<B: Backend, S: CredentialStore, P: UserPresence>(
        &mut self,
        auth: &mut Authenticator<B, S, P>,
        request: &[u8],
    ) -> Result<(Vec<u8>, HidStats), String> {
        let cid = self.cid.ok_or("not connected")?;
        let pkts = fragment(cid, Command::Cbor, request).map_err(|e| e.to_string())?;
        let mut stats = HidStats {
            out_packets: pkts.len(),
            in_packets: 0,
        };
        let mut job = None;
        for (i, p) in pkts.iter().enumerate() {
            match self.server.handle_report(p, self.now_ms) {
                Action::None if i + 1 < pkts.len() => {}
                Action::Process {
                    cid: c,
                    cmd: Command::Cbor,
                    payload,
                } if i + 1 == pkts.len() && c == cid => job = Some(payload),
                other => return Err(format!("unexpected action at packet {i}: {other:?}")),
            }
        }
        let payload = job.ok_or("no request surfaced")?;
        let resp = auth.process(&Bytes::new(payload), self.now_ms);
        let out = self
            .server
            .response(cid, Command::Cbor, &resp)
            .map_err(|e| e.to_string())?;
        stats.in_packets = out.len();
        let m = collect(&out)?;
        if m.cid != cid || m.cmd != Command::Cbor as u8 {
            return Err(format!("reply on wrong channel or command: {m:?}"));
        }
        Ok((m.payload.to_vec(), stats))
    }
}
