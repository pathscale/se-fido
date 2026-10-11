use ciborium::value::Value;
use ctap2::authdata::{rp_id_hash, FLAG_AT, FLAG_UP, FLAG_UV};
use ctap2::cbor::{bytes, decode, int, text, to_canonical_vec, MapView};
use ctap2::soft::{MemoryStore, ScriptedPresence, SoftBackend};
use ctap2::*;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

type Auth = Authenticator<SoftBackend, MemoryStore, ScriptedPresence>;

fn auth() -> Auth {
    Authenticator::new(
        SoftBackend::new(),
        MemoryStore::new(),
        ScriptedPresence::approve(),
        AuthenticatorConfig::default(),
    )
}

const CDH: [u8; 32] = [0x11; 32];

fn req(cmd: u8, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = vec![cmd];
    out.extend(to_canonical_vec(Value::Map(params)));
    out
}

fn mc_params(
    rp: &str,
    user_id: &[u8],
    rk: bool,
    extra: Vec<(Value, Value)>,
) -> Vec<(Value, Value)> {
    let mut p = vec![
        (int(1), bytes(&CDH)),
        (
            int(2),
            Value::Map(vec![
                (text("id"), text(rp)),
                (text("name"), text("Example")),
            ]),
        ),
        (
            int(3),
            Value::Map(vec![
                (text("id"), bytes(user_id)),
                (text("name"), text("alice@example.com")),
                (text("displayName"), text("Alice")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![
                Value::Map(vec![
                    (text("alg"), int(-8)),
                    (text("type"), text("public-key")),
                ]),
                Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ]),
            ]),
        ),
    ];
    if rk {
        p.push((int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])));
    }
    p.extend(extra);
    p
}

fn ok_map(resp: &[u8]) -> Value {
    assert_eq!(resp[0], 0, "status 0x{:02x}", resp[0]);
    decode(&resp[1..]).unwrap()
}

fn get(v: &Value, k: i64) -> &Value {
    MapView::from_value(v)
        .unwrap()
        .get_int_key(k)
        .unwrap_or_else(|| panic!("missing key {k}"))
}

struct Made {
    cred_id: Vec<u8>,
    pubkey: VerifyingKey,
}

/// Register and verify the attestation like a relying party would.
fn make(a: &mut Auth, rp: &str, user: &[u8], rk: bool) -> Made {
    let v = ok_map(&a.process(&req(0x01, mc_params(rp, user, rk, vec![]))));
    assert_eq!(get(&v, 1).as_text().unwrap(), "packed");
    let ad = get(&v, 2).as_bytes().unwrap().clone();
    assert_eq!(&ad[..32], &rp_id_hash(rp));
    assert_eq!(ad[32] & (FLAG_UP | FLAG_AT), FLAG_UP | FLAG_AT);
    assert_eq!(&ad[37..53], &AAGUID);
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    assert_eq!(len, CREDENTIAL_ID_LEN);
    let cred_id = ad[55..55 + len].to_vec();
    let cose = decode(&ad[55 + len..]).unwrap();
    assert_eq!(get(&cose, 1), &int(2));
    assert_eq!(get(&cose, 3), &int(-7));
    assert_eq!(get(&cose, -1), &int(1));
    let mut sec1 = vec![4u8];
    sec1.extend(get(&cose, -2).as_bytes().unwrap());
    sec1.extend(get(&cose, -3).as_bytes().unwrap());
    let pubkey = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let st = get(&v, 3);
    let st = MapView::from_value(st).unwrap();
    assert_eq!(st.get_text_key("alg").unwrap(), &int(-7));
    let sig = Signature::from_der(st.get_text_key("sig").unwrap().as_bytes().unwrap()).unwrap();
    let mut msg = ad.clone();
    msg.extend_from_slice(&CDH);
    pubkey
        .verify(&msg, &sig)
        .expect("self attestation verifies");
    Made { cred_id, pubkey }
}

fn ga_params(rp: &str, allow: &[&[u8]], opts: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
    let mut p = vec![(int(1), text(rp)), (int(2), bytes(&CDH))];
    if !allow.is_empty() {
        p.push((
            int(3),
            Value::Array(
                allow
                    .iter()
                    .map(|id| {
                        Value::Map(vec![
                            (text("id"), bytes(id)),
                            (text("type"), text("public-key")),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    if !opts.is_empty() {
        p.push((int(5), Value::Map(opts)));
    }
    p
}

fn verify_assertion(v: &Value, rp: &str, key: &VerifyingKey) -> (u8, u32) {
    let ad = get(v, 2).as_bytes().unwrap();
    assert_eq!(ad.len(), 37);
    assert_eq!(&ad[..32], &rp_id_hash(rp));
    let sig = Signature::from_der(get(v, 3).as_bytes().unwrap()).unwrap();
    let mut msg = ad.clone();
    msg.extend_from_slice(&CDH);
    key.verify(&msg, &sig)
        .expect("assertion signature verifies");
    (ad[32], u32::from_be_bytes(ad[33..37].try_into().unwrap()))
}

fn cred_id_of(v: &Value) -> Vec<u8> {
    MapView::from_value(get(v, 1))
        .unwrap()
        .get_text_key("id")
        .unwrap()
        .as_bytes()
        .unwrap()
        .clone()
}

#[test]
fn get_info_contents() {
    let mut a = auth();
    let v = ok_map(&a.process(&[0x04]));
    assert_eq!(get(&v, 1), &Value::Array(vec![text("FIDO_2_0")]));
    assert_eq!(get(&v, 3).as_bytes().unwrap(), &AAGUID.to_vec());
    let o = MapView::from_value(get(&v, 4)).unwrap();
    assert_eq!(o.get_text_key("rk"), Some(&Value::Bool(true)));
    assert_eq!(o.get_text_key("up"), Some(&Value::Bool(true)));
    assert_eq!(o.get_text_key("uv"), Some(&Value::Bool(true)));
    assert_eq!(o.get_text_key("plat"), Some(&Value::Bool(false)));
    assert!(o.get_text_key("clientPin").is_none());
    assert_eq!(get(&v, 5), &int(7609));
    // Output is canonical: re-encoding gives identical bytes.
    let resp = a.process(&[0x04]);
    assert_eq!(to_canonical_vec(decode(&resp[1..]).unwrap()), resp[1..]);
}

#[test]
fn aaguid_is_ours_and_v4() {
    assert_eq!(AAGUID[6] >> 4, 4, "UUID version 4");
    assert_eq!(AAGUID[8] & 0xc0, 0x80, "RFC 4122 variant");
}

#[test]
fn register_then_authenticate_with_allow_list() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"user1", false);
    let v = ok_map(&a.process(&req(0x02, ga_params("example.com", &[&m.cred_id], vec![]))));
    assert_eq!(cred_id_of(&v), m.cred_id);
    let (flags, c1) = verify_assertion(&v, "example.com", &m.pubkey);
    assert_eq!(flags, FLAG_UP);
    assert!(
        MapView::from_value(&v).unwrap().get_int_key(4).is_none(),
        "no user for non-resident"
    );
    let v = ok_map(&a.process(&req(0x02, ga_params("example.com", &[&m.cred_id], vec![]))));
    let (_, c2) = verify_assertion(&v, "example.com", &m.pubkey);
    assert!(c2 > c1, "counter must increase");
}

#[test]
fn allow_list_for_other_rp_does_not_match() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"user1", false);
    let r = a.process(&req(0x02, ga_params("evil.com", &[&m.cred_id], vec![])));
    assert_eq!(r, [Status::NoCredentials.code()]);
}

#[test]
fn unknown_credential_is_no_credentials() {
    let mut a = auth();
    let r = a.process(&req(0x02, ga_params("example.com", &[&[1, 2, 3]], vec![])));
    assert_eq!(r, [Status::NoCredentials.code()]);
    let r = a.process(&req(0x02, ga_params("example.com", &[], vec![])));
    assert_eq!(r, [Status::NoCredentials.code()]);
}

#[test]
fn discoverable_credentials_and_get_next_assertion() {
    let mut a = auth();
    let m1 = make(&mut a, "example.com", b"u1", true);
    let m2 = make(&mut a, "example.com", b"u2", true);
    let _other = make(&mut a, "other.com", b"u3", true);
    let _nonrk = make(&mut a, "example.com", b"u4", false);
    let v = ok_map(&a.process(&req(0x02, ga_params("example.com", &[], vec![]))));
    assert_eq!(get(&v, 5), &int(2));
    // Most recent first.
    assert_eq!(cred_id_of(&v), m2.cred_id);
    verify_assertion(&v, "example.com", &m2.pubkey);
    let user = MapView::from_value(get(&v, 4)).unwrap();
    assert_eq!(user.get_text_key("id").unwrap().as_bytes().unwrap(), b"u2");
    assert!(user.get_text_key("name").is_none(), "no PII without UV");
    let v = ok_map(&a.process(&[0x08]));
    assert_eq!(cred_id_of(&v), m1.cred_id);
    verify_assertion(&v, "example.com", &m1.pubkey);
    assert!(MapView::from_value(&v).unwrap().get_int_key(5).is_none());
    assert_eq!(a.process(&[0x08]), [Status::NotAllowed.code()]);
}

#[test]
fn get_next_assertion_state_cleared_by_other_command() {
    let mut a = auth();
    make(&mut a, "example.com", b"u1", true);
    make(&mut a, "example.com", b"u2", true);
    ok_map(&a.process(&req(0x02, ga_params("example.com", &[], vec![]))));
    ok_map(&a.process(&[0x04]));
    assert_eq!(a.process(&[0x08]), [Status::NotAllowed.code()]);
}

#[test]
fn get_next_without_state_not_allowed() {
    assert_eq!(auth().process(&[0x08]), [Status::NotAllowed.code()]);
}

#[test]
fn uv_sets_flag_and_reveals_user_info() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"u1", true);
    let v = ok_map(&a.process(&req(
        0x02,
        ga_params("example.com", &[], vec![(text("uv"), Value::Bool(true))]),
    )));
    let (flags, _) = verify_assertion(&v, "example.com", &m.pubkey);
    assert_eq!(flags, FLAG_UP | FLAG_UV);
    let user = MapView::from_value(get(&v, 4)).unwrap();
    assert_eq!(user.get_text_key("name"), Some(&text("alice@example.com")));
    assert_eq!(user.get_text_key("displayName"), Some(&text("Alice")));
    assert!(a.presence().requests.last().unwrap().require_uv);
}

#[test]
fn make_credential_uv_flag() {
    let mut a = auth();
    let v = ok_map(&a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(7), Value::Map(vec![(text("uv"), Value::Bool(true))]))],
        ),
    )));
    let ad = get(&v, 2).as_bytes().unwrap();
    assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_AT);
}

#[test]
fn silent_assertion_up_false() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"u1", false);
    let before = a.presence().requests.len();
    let v = ok_map(&a.process(&req(
        0x02,
        ga_params(
            "example.com",
            &[&m.cred_id],
            vec![(text("up"), Value::Bool(false))],
        ),
    )));
    let (flags, _) = verify_assertion(&v, "example.com", &m.pubkey);
    assert_eq!(flags, 0);
    assert_eq!(
        a.presence().requests.len(),
        before,
        "no presence prompt for up=false"
    );
}

#[test]
fn uv_required_but_not_performed_is_denied() {
    let mut a = Authenticator::new(
        SoftBackend::new(),
        MemoryStore::new(),
        ScriptedPresence {
            answer: Ok(Presence {
                user_verified: false,
            }),
            requests: vec![],
        },
        AuthenticatorConfig::default(),
    );
    let r = a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(7), Value::Map(vec![(text("uv"), Value::Bool(true))]))],
        ),
    ));
    assert_eq!(r, [Status::OperationDenied.code()]);
}

#[test]
fn uv_unsupported_when_disabled() {
    let mut a = Authenticator::new(
        SoftBackend::new(),
        MemoryStore::new(),
        ScriptedPresence::approve(),
        AuthenticatorConfig {
            builtin_uv: false,
            ..Default::default()
        },
    );
    let v = ok_map(&a.process(&[0x04]));
    assert!(MapView::from_value(get(&v, 4))
        .unwrap()
        .get_text_key("uv")
        .is_none());
    let r = a.process(&req(
        0x02,
        ga_params("x.com", &[], vec![(text("uv"), Value::Bool(true))]),
    ));
    assert_eq!(r, [Status::UnsupportedOption.code()]);
}

#[test]
fn exclude_list_hit() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"u1", false);
    let excl = (
        int(5),
        Value::Array(vec![Value::Map(vec![
            (text("id"), bytes(&m.cred_id)),
            (text("type"), text("public-key")),
        ])]),
    );
    let r = a.process(&req(
        0x01,
        mc_params("example.com", b"u2", false, vec![excl.clone()]),
    ));
    assert_eq!(r, [Status::CredentialExcluded.code()]);
    assert_eq!(
        a.presence().requests.last().unwrap().kind,
        PresenceKind::Excluded
    );
    // Same credential ID for a different RP does not exclude.
    ok_map(&a.process(&req(0x01, mc_params("other.com", b"u2", false, vec![excl]))));
}

#[test]
fn resident_credential_for_same_user_is_replaced() {
    let mut a = auth();
    let m1 = make(&mut a, "example.com", b"u1", true);
    let m2 = make(&mut a, "example.com", b"u1", true);
    assert_eq!(a.store().len(), 1);
    assert_eq!(a.backend().key_count(), 1);
    let v = ok_map(&a.process(&req(0x02, ga_params("example.com", &[], vec![]))));
    assert_eq!(cred_id_of(&v), m2.cred_id);
    assert_ne!(m1.cred_id, m2.cred_id);
}

#[test]
fn unsupported_algorithm() {
    let mut a = auth();
    let mut p = mc_params("x.com", b"u", false, vec![]);
    p[3] = (
        int(4),
        Value::Array(vec![Value::Map(vec![
            (text("alg"), int(-257)),
            (text("type"), text("public-key")),
        ])]),
    );
    assert_eq!(
        a.process(&req(0x01, p)),
        [Status::UnsupportedAlgorithm.code()]
    );
}

#[test]
fn missing_and_mistyped_parameters() {
    let mut a = auth();
    for drop in 0..4 {
        let mut p = mc_params("x.com", b"u", false, vec![]);
        p.remove(drop);
        assert_eq!(
            a.process(&req(0x01, p)),
            [Status::MissingParameter.code()],
            "dropping index {drop}"
        );
    }
    let mut p = mc_params("x.com", b"u", false, vec![]);
    p[0] = (int(1), text("not bytes"));
    assert_eq!(
        a.process(&req(0x01, p)),
        [Status::CborUnexpectedType.code()]
    );
    assert_eq!(a.process(&[0x01]), [Status::MissingParameter.code()]);
    assert_eq!(
        a.process(&[0x01, 0x01]),
        [Status::CborUnexpectedType.code()]
    );
    assert_eq!(a.process(&[0x01, 0xa1]), [Status::InvalidCbor.code()]);
    assert_eq!(
        a.process(&req(0x02, vec![(int(1), text("x.com"))])),
        [Status::MissingParameter.code()]
    );
}

#[test]
fn user_id_too_long() {
    let mut a = auth();
    assert_eq!(
        a.process(&req(0x01, mc_params("x.com", &[0; 65], false, vec![]))),
        [Status::InvalidLength.code()]
    );
    ok_map(&a.process(&req(0x01, mc_params("x.com", &[0; 64], false, vec![]))));
}

#[test]
fn option_errors() {
    let mut a = auth();
    let r = a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(7), Value::Map(vec![(text("up"), Value::Bool(false))]))],
        ),
    ));
    assert_eq!(r, [Status::InvalidOption.code()]);
    let r = a.process(&req(
        0x02,
        ga_params("x.com", &[], vec![(text("rk"), Value::Bool(true))]),
    ));
    assert_eq!(r, [Status::UnsupportedOption.code()]);
    let r = a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(7), Value::Map(vec![(text("rk"), int(1))]))],
        ),
    ));
    assert_eq!(r, [Status::CborUnexpectedType.code()]);
    // Unknown options are ignored.
    ok_map(&a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(7), Value::Map(vec![(text("foo"), Value::Bool(true))]))],
        ),
    )));
}

#[test]
fn enterprise_attestation_rejected() {
    let mut a = auth();
    let r = a.process(&req(
        0x01,
        mc_params("x.com", b"u", false, vec![(int(0x0a), int(1))]),
    ));
    assert_eq!(r, [Status::InvalidParameter.code()]);
}

#[test]
fn presence_errors_map_to_statuses() {
    for (err, status) in [
        (PresenceError::Denied, Status::OperationDenied),
        (PresenceError::UvFailed, Status::OperationDenied),
        (PresenceError::Cancelled, Status::KeepaliveCancel),
        (PresenceError::Timeout, Status::UserActionTimeout),
    ] {
        let mut a = Authenticator::new(
            SoftBackend::new(),
            MemoryStore::new(),
            ScriptedPresence::deny(err),
            AuthenticatorConfig::default(),
        );
        assert_eq!(
            a.process(&req(0x01, mc_params("x.com", b"u", false, vec![]))),
            [status.code()]
        );
        assert_eq!(a.store().len(), 0);
        assert_eq!(a.backend().key_count(), 0);
        assert_eq!(a.process(&[0x0b]), [status.code()]);
    }
}

#[test]
fn pin_uv_auth_param_probe_and_rejection() {
    let mut a = auth();
    let r = a.process(&req(
        0x01,
        mc_params("x.com", b"u", false, vec![(int(8), bytes(&[]))]),
    ));
    assert_eq!(r, [Status::PinNotSet.code()]);
    assert_eq!(
        a.presence().requests.last().unwrap().kind,
        PresenceKind::Probe
    );
    let r = a.process(&req(
        0x01,
        mc_params("x.com", b"u", false, vec![(int(8), bytes(&[1; 16]))]),
    ));
    assert_eq!(r, [Status::MissingParameter.code()]);
    let r = a.process(&req(
        0x01,
        mc_params(
            "x.com",
            b"u",
            false,
            vec![(int(8), bytes(&[1; 16])), (int(9), int(1))],
        ),
    ));
    assert_eq!(r, [Status::InvalidParameter.code()]);
    assert_eq!(a.store().len(), 0);
}

#[test]
fn attestation_none_format() {
    let mut a = Authenticator::new(
        SoftBackend::new(),
        MemoryStore::new(),
        ScriptedPresence::approve(),
        AuthenticatorConfig {
            attestation: AttestationFormat::None,
            ..Default::default()
        },
    );
    let v = ok_map(&a.process(&req(0x01, mc_params("x.com", b"u", false, vec![]))));
    assert_eq!(get(&v, 1), &text("none"));
    assert_eq!(get(&v, 3), &Value::Map(vec![]));
}

#[test]
fn store_full() {
    let mut a = Authenticator::new(
        SoftBackend::new(),
        MemoryStore::with_capacity_limit(1),
        ScriptedPresence::approve(),
        AuthenticatorConfig::default(),
    );
    ok_map(&a.process(&req(0x01, mc_params("x.com", b"u", false, vec![]))));
    assert_eq!(
        a.process(&req(0x01, mc_params("x.com", b"v", false, vec![]))),
        [Status::KeyStoreFull.code()]
    );
    assert_eq!(
        a.backend().key_count(),
        1,
        "key of failed registration is deleted"
    );
}

#[test]
fn reset_wipes_credentials_and_keys() {
    let mut a = auth();
    let m = make(&mut a, "example.com", b"u1", true);
    make(&mut a, "example.com", b"u2", false);
    let counter_before = a.store().counter();
    assert_eq!(a.process(&[0x07]), [0]);
    assert_eq!(a.store().len(), 0);
    assert_eq!(a.backend().key_count(), 0);
    assert_eq!(a.store().counter(), counter_before, "counter not reset");
    assert_eq!(
        a.process(&req(0x02, ga_params("example.com", &[&m.cred_id], vec![]))),
        [Status::NoCredentials.code()]
    );
}

#[test]
fn reset_requires_presence() {
    let mut a = Authenticator::new(
        SoftBackend::new(),
        MemoryStore::new(),
        ScriptedPresence::deny(PresenceError::Denied),
        AuthenticatorConfig::default(),
    );
    assert_eq!(a.process(&[0x07]), [Status::OperationDenied.code()]);
}

#[test]
fn selection_and_unknown_commands() {
    let mut a = auth();
    assert_eq!(a.process(&[0x0b]), [0]);
    assert_eq!(a.process(&[0x06, 0xa0]), [Status::InvalidCommand.code()]);
    assert_eq!(a.process(&[0x40]), [Status::InvalidCommand.code()]);
    assert_eq!(a.process(&[]), [Status::InvalidLength.code()]);
}

#[test]
fn long_names_truncated_on_char_boundary() {
    let mut a = auth();
    let long = "é".repeat(40); // 80 bytes
    let mut p = mc_params("x.com", b"u", true, vec![]);
    p[2] = (
        int(3),
        Value::Map(vec![(text("id"), bytes(b"u")), (text("name"), text(&long))]),
    );
    ok_map(&a.process(&req(0x01, p)));
    let v = ok_map(&a.process(&req(
        0x02,
        ga_params("x.com", &[], vec![(text("uv"), Value::Bool(true))]),
    )));
    let name = MapView::from_value(get(&v, 4))
        .unwrap()
        .get_text_key("name")
        .unwrap()
        .as_text()
        .unwrap()
        .to_owned();
    assert_eq!(name.len(), 64);
    assert!(name.chars().all(|c| c == 'é'));
}

/// Backend that returns garbage signatures: must never reach the RP.
struct BadSigBackend(SoftBackend);
impl Backend for BadSigBackend {
    fn create_key(&mut self, rp: &str, u: &[u8]) -> Result<NewKey, BackendError> {
        self.0.create_key(rp, u)
    }
    fn sign(&mut self, h: &[u8], m: &[u8]) -> Result<Vec<u8>, BackendError> {
        let mut other = m.to_vec();
        other.push(0);
        self.0.sign(h, &other)
    }
    fn delete_key(&mut self, h: &[u8]) -> Result<(), BackendError> {
        self.0.delete_key(h)
    }
}

#[test]
fn bad_backend_signature_is_caught() {
    let mut a = Authenticator::new(
        BadSigBackend(SoftBackend::new()),
        MemoryStore::new(),
        ScriptedPresence::approve(),
        AuthenticatorConfig::default(),
    );
    assert_eq!(
        a.process(&req(0x01, mc_params("x.com", b"u", false, vec![]))),
        [Status::Other.code()]
    );
}

#[test]
fn failed_attestation_leaves_no_credential_or_key() {
    let mut a = Authenticator::new(
        BadSigBackend(SoftBackend::new()),
        MemoryStore::new(),
        ScriptedPresence::approve(),
        AuthenticatorConfig::default(),
    );
    a.process(&req(0x01, mc_params("x.com", b"u", false, vec![])));
    assert_eq!(a.store().len(), 0);
    assert_eq!(a.backend().0.key_count(), 0);
}
