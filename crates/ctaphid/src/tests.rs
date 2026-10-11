use super::*;

const NOW: u64 = 1_000;

fn init_packet(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> Packet {
    let mut p = [0u8; REPORT_SIZE];
    p[0..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = TYPE_INIT | cmd;
    p[5..7].copy_from_slice(&bcnt.to_be_bytes());
    p[7..7 + data.len()].copy_from_slice(data);
    p
}

fn cont_packet(cid: u32, seq: u8, data: &[u8]) -> Packet {
    let mut p = [0u8; REPORT_SIZE];
    p[0..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = seq;
    p[5..5 + data.len()].copy_from_slice(data);
    p
}

fn sent(a: Action) -> Vec<Packet> {
    match a {
        Action::Send(p) => p,
        other => panic!("expected Send, got {other:?}"),
    }
}

fn single_error(a: Action) -> (u32, u8) {
    let p = sent(a);
    assert_eq!(p.len(), 1);
    let m = Reassembler::default().push(&p[0]).unwrap().unwrap();
    assert_eq!(m.cmd, Command::Error as u8, "not an error packet: {m:?}");
    assert_eq!(m.payload.len(), 1);
    (m.cid, m.payload[0])
}

/// Allocate a channel through the broadcast CID and return it.
fn open_channel(s: &mut Server) -> u32 {
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let out = sent(s.handle_report(
        &init_packet(BROADCAST_CID, Command::Init as u8, 8, &nonce),
        NOW,
    ));
    assert_eq!(out.len(), 1);
    let m = Reassembler::default().push(&out[0]).unwrap().unwrap();
    assert_eq!(m.cid, BROADCAST_CID);
    assert_eq!(m.cmd, Command::Init as u8);
    assert_eq!(m.payload.len(), 17);
    assert_eq!(&m.payload[0..8], &nonce);
    u32::from_be_bytes(m.payload[8..12].try_into().unwrap())
}

fn feed_all(s: &mut Server, packets: &[Packet]) -> Action {
    let mut last = Action::None;
    for (i, p) in packets.iter().enumerate() {
        last = s.handle_report(p, NOW + i as u64);
        if i + 1 < packets.len() {
            assert_eq!(
                last,
                Action::None,
                "intermediate packet {i} produced output"
            );
        }
    }
    last
}

#[test]
fn constants_match_spec() {
    assert_eq!(INIT_DATA_SIZE, 57);
    assert_eq!(CONT_DATA_SIZE, 59);
    assert_eq!(MAX_MESSAGE_SIZE, 7609);
}

#[test]
fn init_allocates_distinct_channels_and_reports_version() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let b = open_channel(&mut s);
    assert_ne!(a, b);
    assert_ne!(a, 0);
    assert_ne!(a, BROADCAST_CID);
    let out = sent(s.handle_report(&init_packet(BROADCAST_CID, 0x06, 8, &[0; 8]), NOW));
    let m = Reassembler::default().push(&out[0]).unwrap().unwrap();
    assert_eq!(m.payload[12], PROTOCOL_VERSION);
    assert_eq!(
        m.payload[16],
        CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG
    );
}

#[test]
fn init_on_allocated_channel_resyncs_same_cid() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let out = sent(s.handle_report(&init_packet(cid, 0x06, 8, &[9; 8]), NOW));
    let m = Reassembler::default().push(&out[0]).unwrap().unwrap();
    assert_eq!(m.cid, cid);
    assert_eq!(
        u32::from_be_bytes(m.payload[8..12].try_into().unwrap()),
        cid
    );
}

#[test]
fn init_wrong_length_is_invalid_len() {
    let mut s = Server::new(Config::default());
    let (_, code) =
        single_error(s.handle_report(&init_packet(BROADCAST_CID, 0x06, 7, &[0; 7]), NOW));
    assert_eq!(code, ErrorCode::InvalidLen as u8);
}

#[test]
fn init_on_unknown_channel_is_invalid_channel() {
    let mut s = Server::new(Config::default());
    let (_, code) = single_error(s.handle_report(&init_packet(0x1234, 0x06, 8, &[0; 8]), NOW));
    assert_eq!(code, ErrorCode::InvalidChannel as u8);
}

#[test]
fn cid_zero_and_broadcast_non_init_rejected() {
    let mut s = Server::new(Config::default());
    let (_, code) = single_error(s.handle_report(&init_packet(0, 0x01, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidChannel as u8);
    let (_, code) = single_error(s.handle_report(&init_packet(BROADCAST_CID, 0x01, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidChannel as u8);
}

#[test]
fn unallocated_channel_rejected() {
    let mut s = Server::new(Config::default());
    let (cid, code) = single_error(s.handle_report(&init_packet(0xdead_beef, 0x10, 1, &[4]), NOW));
    assert_eq!(cid, 0xdead_beef);
    assert_eq!(code, ErrorCode::InvalidChannel as u8);
}

#[test]
fn ping_roundtrip_all_boundary_sizes() {
    for len in [
        0usize,
        1,
        56,
        57,
        58,
        115,
        116,
        117,
        1000,
        MAX_MESSAGE_SIZE - 1,
        MAX_MESSAGE_SIZE,
    ] {
        let mut s = Server::new(Config::default());
        let cid = open_channel(&mut s);
        let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let pkts = fragment(cid, Command::Ping, &payload).unwrap();
        let expected_packets = if len <= INIT_DATA_SIZE {
            1
        } else {
            1 + (len - INIT_DATA_SIZE).div_ceil(CONT_DATA_SIZE)
        };
        assert_eq!(pkts.len(), expected_packets, "len {len}");
        let out = sent(feed_all(&mut s, &pkts));
        let mut r = Reassembler::default();
        let mut msg = None;
        for p in &out {
            msg = r.push(p).unwrap();
        }
        let m = msg.expect("complete");
        assert_eq!(m.cmd, Command::Ping as u8);
        assert_eq!(m.payload, payload, "len {len}");
    }
}

#[test]
fn fragment_rejects_oversize() {
    assert_eq!(
        fragment(1, Command::Cbor, &vec![0; MAX_MESSAGE_SIZE + 1]),
        Err(FrameError::TooLong(MAX_MESSAGE_SIZE + 1))
    );
}

#[test]
fn fragment_pads_with_zero_and_numbers_sequence() {
    let pkts = fragment(0x01020304, Command::Cbor, &[0xaa; 200]).unwrap();
    assert_eq!(pkts.len(), 4); // 57 + 59 + 59 + 25
    assert_eq!(&pkts[0][0..7], &[1, 2, 3, 4, 0x90, 0, 200]);
    for (i, p) in pkts[1..].iter().enumerate() {
        assert_eq!(p[4], i as u8);
    }
    assert!(pkts[3][5 + 25..].iter().all(|&b| b == 0));
    assert!(pkts[3][5..5 + 25].iter().all(|&b| b == 0xaa));
}

#[test]
fn oversize_bcnt_rejected() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let (_, code) = single_error(s.handle_report(
        &init_packet(cid, 0x10, (MAX_MESSAGE_SIZE + 1) as u16, &[]),
        NOW,
    ));
    assert_eq!(code, ErrorCode::InvalidLen as u8);
}

#[test]
fn cbor_request_is_surfaced_and_channel_becomes_busy() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let other = open_channel(&mut s);
    let payload = vec![0x04];
    match s.handle_report(&init_packet(cid, 0x10, 1, &payload), NOW) {
        Action::Process {
            cid: c,
            cmd,
            payload: p,
        } => {
            assert_eq!(c, cid);
            assert_eq!(cmd, Command::Cbor);
            assert_eq!(p, payload);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(s.busy_channel(), Some(cid));
    // Another channel is told the device is busy.
    let (c, code) = single_error(s.handle_report(&init_packet(other, 0x10, 1, &[4]), NOW));
    assert_eq!((c, code), (other, ErrorCode::ChannelBusy as u8));
    // Same channel too.
    let (_, code) = single_error(s.handle_report(&init_packet(cid, 0x01, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::ChannelBusy as u8);
    // Respond and the channel frees.
    let out = s.response(cid, Command::Cbor, &[0x00]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(s.busy_channel(), None);
    assert!(matches!(
        s.handle_report(&init_packet(other, 0x10, 1, &[4]), NOW),
        Action::Process { .. }
    ));
}

#[test]
fn empty_cbor_is_invalid_len() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let (_, code) = single_error(s.handle_report(&init_packet(cid, 0x10, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidLen as u8);
}

#[test]
fn cancel_on_busy_channel_reports_cancel_without_reply() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let other = open_channel(&mut s);
    assert!(matches!(
        s.handle_report(&init_packet(cid, 0x10, 1, &[1]), NOW),
        Action::Process { .. }
    ));
    // Cancel from a different channel is ignored.
    assert_eq!(
        s.handle_report(&init_packet(other, 0x11, 0, &[]), NOW),
        Action::None
    );
    assert_eq!(
        s.handle_report(&init_packet(cid, 0x11, 0, &[]), NOW),
        Action::Cancel { cid }
    );
    // Still busy until the application answers.
    assert_eq!(s.busy_channel(), Some(cid));
    s.abort(cid);
    assert_eq!(s.busy_channel(), None);
}

#[test]
fn cancel_during_assembly_discards_partial_message() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[5; 100]).unwrap();
    assert_eq!(s.handle_report(&pkts[0], NOW), Action::None);
    assert_eq!(
        s.handle_report(&init_packet(cid, 0x11, 0, &[]), NOW),
        Action::None
    );
    // Continuation is now spurious and ignored.
    assert_eq!(s.handle_report(&pkts[1], NOW), Action::None);
}

#[test]
fn wrong_sequence_aborts_with_invalid_seq() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[1; 200]).unwrap();
    assert_eq!(s.handle_report(&pkts[0], NOW), Action::None);
    // Skip seq 0, send seq 1.
    let (_, code) = single_error(s.handle_report(&pkts[2], NOW));
    assert_eq!(code, ErrorCode::InvalidSeq as u8);
    // Assembly was dropped: a later continuation is ignored.
    assert_eq!(s.handle_report(&pkts[1], NOW), Action::None);
}

#[test]
fn repeated_sequence_number_is_invalid_seq() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[1; 200]).unwrap();
    s.handle_report(&pkts[0], NOW);
    assert_eq!(s.handle_report(&pkts[1], NOW), Action::None);
    let (_, code) = single_error(s.handle_report(&pkts[1], NOW));
    assert_eq!(code, ErrorCode::InvalidSeq as u8);
}

#[test]
fn new_init_packet_mid_message_on_same_channel_is_invalid_seq() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[1; 100]).unwrap();
    s.handle_report(&pkts[0], NOW);
    let (_, code) = single_error(s.handle_report(&init_packet(cid, 0x01, 1, &[1]), NOW));
    assert_eq!(code, ErrorCode::InvalidSeq as u8);
}

#[test]
fn other_channel_during_assembly_is_busy_and_does_not_disturb() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let b = open_channel(&mut s);
    let payload: Vec<u8> = (0..150u8).collect();
    let pkts = fragment(a, Command::Ping, &payload).unwrap();
    s.handle_report(&pkts[0], NOW);
    let (c, code) = single_error(s.handle_report(&init_packet(b, 0x01, 1, &[1]), NOW));
    assert_eq!((c, code), (b, ErrorCode::ChannelBusy as u8));
    let (c, code) = single_error(s.handle_report(&cont_packet(b, 0, &[0]), NOW));
    assert_eq!((c, code), (b, ErrorCode::ChannelBusy as u8));
    s.handle_report(&pkts[1], NOW);
    let out = sent(s.handle_report(&pkts[2], NOW));
    let mut r = Reassembler::default();
    let mut m = None;
    for p in &out {
        m = r.push(p).unwrap();
    }
    assert_eq!(m.unwrap().payload, payload);
}

#[test]
fn broadcast_init_allowed_during_assembly() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let pkts = fragment(a, Command::Ping, &[3; 80]).unwrap();
    s.handle_report(&pkts[0], NOW);
    let b = open_channel(&mut s);
    assert_ne!(a, b);
    // The original message can still complete.
    assert!(matches!(s.handle_report(&pkts[1], NOW), Action::Send(_)));
}

#[test]
fn init_on_same_channel_mid_message_resyncs() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let pkts = fragment(a, Command::Ping, &[3; 80]).unwrap();
    s.handle_report(&pkts[0], NOW);
    assert!(matches!(
        s.handle_report(&init_packet(a, 0x06, 8, &[0; 8]), NOW),
        Action::Send(_)
    ));
    assert_eq!(
        s.handle_report(&pkts[1], NOW),
        Action::None,
        "old continuation must be ignored after resync"
    );
}

#[test]
fn spurious_continuation_is_ignored() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    assert_eq!(
        s.handle_report(&cont_packet(cid, 0, &[1, 2, 3]), NOW),
        Action::None
    );
}

#[test]
fn continuation_timeout_produces_msg_timeout() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[1; 100]).unwrap();
    s.handle_report(&pkts[0], NOW);
    assert!(
        s.poll(NOW + 1000).is_empty(),
        "exactly at the limit is still fine"
    );
    let out = s.poll(NOW + 1001);
    assert_eq!(out.len(), 1);
    let m = Reassembler::default().push(&out[0]).unwrap().unwrap();
    assert_eq!(
        (m.cid, m.cmd, m.payload[0]),
        (cid, Command::Error as u8, ErrorCode::MsgTimeout as u8)
    );
    assert_eq!(s.handle_report(&pkts[1], NOW + 1002), Action::None);
}

#[test]
fn timeout_detected_lazily_on_next_report() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let b = open_channel(&mut s);
    let pkts = fragment(a, Command::Ping, &[1; 100]).unwrap();
    s.handle_report(&pkts[0], NOW);
    let out = sent(s.handle_report(&init_packet(b, 0x01, 1, &[7]), NOW + 5000));
    assert_eq!(out.len(), 2);
    let e = Reassembler::default().push(&out[0]).unwrap().unwrap();
    assert_eq!((e.cid, e.payload[0]), (a, ErrorCode::MsgTimeout as u8));
    let pong = Reassembler::default().push(&out[1]).unwrap().unwrap();
    assert_eq!((pong.cid, pong.payload.as_slice()), (b, &[7u8][..]));
}

#[test]
fn slow_but_steady_continuations_do_not_time_out() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let pkts = fragment(cid, Command::Ping, &[1; 300]).unwrap();
    let mut t = NOW;
    let mut last = Action::None;
    for p in &pkts {
        last = s.handle_report(p, t);
        t += 900;
    }
    assert!(matches!(last, Action::Send(_)));
}

#[test]
fn unknown_command_is_invalid_cmd() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let (_, code) = single_error(s.handle_report(&init_packet(cid, 0x55, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidCmd as u8);
}

#[test]
fn msg_rejected_when_nmsg() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    let (_, code) = single_error(s.handle_report(&init_packet(cid, 0x03, 1, &[0]), NOW));
    assert_eq!(code, ErrorCode::InvalidCmd as u8);
}

#[test]
fn host_to_device_only_commands_rejected() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    for cmd in [Command::Keepalive, Command::Error] {
        let (_, code) = single_error(s.handle_report(&init_packet(cid, cmd as u8, 1, &[1]), NOW));
        assert_eq!(code, ErrorCode::InvalidCmd as u8);
    }
}

#[test]
fn wink_replies_empty() {
    let mut s = Server::new(Config::default());
    let cid = open_channel(&mut s);
    match s.handle_report(&init_packet(cid, 0x08, 0, &[]), NOW) {
        Action::Wink(p) => {
            let m = Reassembler::default().push(&p[0]).unwrap().unwrap();
            assert_eq!((m.cmd, m.payload.len()), (Command::Wink as u8, 0));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn lock_excludes_other_channels_until_expiry() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let b = open_channel(&mut s);
    sent(s.handle_report(&init_packet(a, 0x04, 1, &[2]), NOW));
    let (_, code) = single_error(s.handle_report(&init_packet(b, 0x01, 0, &[]), NOW + 10));
    assert_eq!(code, ErrorCode::ChannelBusy as u8);
    // Owner still works.
    assert!(matches!(
        s.handle_report(&init_packet(a, 0x01, 0, &[]), NOW + 10),
        Action::Send(_)
    ));
    // After 2 s the lock is gone.
    assert!(matches!(
        s.handle_report(&init_packet(b, 0x01, 0, &[]), NOW + 2000),
        Action::Send(_)
    ));
}

#[test]
fn lock_zero_releases_and_bad_values_rejected() {
    let mut s = Server::new(Config::default());
    let a = open_channel(&mut s);
    let b = open_channel(&mut s);
    sent(s.handle_report(&init_packet(a, 0x04, 1, &[10]), NOW));
    sent(s.handle_report(&init_packet(a, 0x04, 1, &[0]), NOW));
    assert!(matches!(
        s.handle_report(&init_packet(b, 0x01, 0, &[]), NOW),
        Action::Send(_)
    ));
    let (_, code) = single_error(s.handle_report(&init_packet(a, 0x04, 1, &[11]), NOW));
    assert_eq!(code, ErrorCode::InvalidPar as u8);
    let (_, code) = single_error(s.handle_report(&init_packet(a, 0x04, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidPar as u8);
}

#[test]
fn channel_table_is_bounded() {
    let mut s = Server::new(Config {
        max_channels: 3,
        ..Config::default()
    });
    let first = open_channel(&mut s);
    for _ in 0..3 {
        open_channel(&mut s);
    }
    assert!(!s.is_allocated(first));
    let (_, code) = single_error(s.handle_report(&init_packet(first, 0x01, 0, &[]), NOW));
    assert_eq!(code, ErrorCode::InvalidChannel as u8);
}

#[test]
fn wrong_report_size_ignored() {
    let mut s = Server::new(Config::default());
    assert_eq!(s.handle_report(&[0u8; 63], NOW), Action::None);
    assert_eq!(s.handle_report(&[0u8; 65], NOW), Action::None);
}

#[test]
fn keepalive_and_error_packets() {
    let k = keepalive_packet(7, KeepaliveStatus::UpNeeded);
    assert_eq!(&k[0..8], &[0, 0, 0, 7, 0xbb, 0, 1, 2]);
    let e = error_packet(7, ErrorCode::ChannelBusy);
    assert_eq!(&e[0..8], &[0, 0, 0, 7, 0xbf, 0, 1, 6]);
}

#[test]
fn reassembler_rejects_bad_input() {
    let mut r = Reassembler::default();
    assert!(r.push(&cont_packet(1, 0, &[])).is_err());
    let pkts = fragment(1, Command::Cbor, &[0; 100]).unwrap();
    r.push(&pkts[0]).unwrap();
    assert!(r.push(&cont_packet(2, 0, &[])).is_err());
    assert!(r.push(&cont_packet(1, 5, &[])).is_err());
}
