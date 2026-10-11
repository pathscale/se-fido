//! Opt-in end-to-end run on the real Secure Enclave. No Touch ID: credentials
//! default to UvPolicy::None (the authenticator default, Presence, would make
//! the SE prompt, which a non-interactive run cannot answer), keys use
//! AccessPolicy::None and presence is simulated (ScriptedPresence). Output
//! is not compared byte for byte (keys and signatures are random); every
//! step is verified relying-party side.

use crate::tmp_root;
use backend_se::{storage_key, AccessPolicy, SeBackend, StorageMode, SystemEntropy};
use ctap2::cbor::{encode, Out};
use ctap2::soft::ScriptedPresence;
use ctap2::{Authenticator, AuthenticatorConfig, UvPolicy};
use se_fido_store::FileStore;
use std::time::Instant;
use transport_test::{rp, Host};

type Auth = Authenticator<SeBackend, FileStore<SystemEntropy>, ScriptedPresence>;

fn open(dir: &std::path::Path) -> Result<Auth, String> {
    let t = Instant::now();
    let key = storage_key(dir).map_err(|e| e.to_string())?;
    println!(
        "storage key derived via SE ECDH + HKDF in {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    let store =
        FileStore::open(dir.join("store"), &key, SystemEntropy).map_err(|e| e.to_string())?;
    Ok(Authenticator::new(
        SeBackend::new(StorageMode::Blob, AccessPolicy::None),
        store,
        ScriptedPresence::approve(),
        AuthenticatorConfig {
            default_uv_policy: UvPolicy::None,
            ..AuthenticatorConfig::default()
        },
    ))
}

fn make_req(cdh: &[u8; 32]) -> Vec<u8> {
    let mut r = vec![0x01];
    r.extend(encode(&Out::Map(vec![
        (Out::Int(1), Out::Bytes(cdh)),
        (
            Out::Int(2),
            Out::Map(vec![(Out::Text("id"), Out::Text("example.com"))]),
        ),
        (
            Out::Int(3),
            Out::Map(vec![
                (Out::Text("id"), Out::Bytes(b"alice")),
                (Out::Text("name"), Out::Text("alice@example.com")),
            ]),
        ),
        (
            Out::Int(4),
            Out::Array(vec![Out::Map(vec![
                (Out::Text("alg"), Out::Int(-7)),
                (Out::Text("type"), Out::Text("public-key")),
            ])]),
        ),
        (
            Out::Int(7),
            Out::Map(vec![(Out::Text("rk"), Out::Bool(true))]),
        ),
    ])));
    r
}

fn get_req(cdh: &[u8; 32]) -> Vec<u8> {
    let mut r = vec![0x02];
    r.extend(encode(&Out::Map(vec![
        (Out::Int(1), Out::Text("example.com")),
        (Out::Int(2), Out::Bytes(cdh)),
    ])));
    r
}

fn run_inner(dir: &std::path::Path) -> Result<(), String> {
    let mut auth = open(dir)?;
    let mut host = Host::new();
    host.connect([9; 8])?;
    let (_, cdh) = rp::client_data(
        "webauthn.create",
        "c2UtZmlkby1jcmVhdGU",
        "https://example.com",
    );
    let t = Instant::now();
    let (resp, stats) = host.transact(&mut auth, &make_req(&cdh))?;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    if resp[0] != 0 {
        return Err(format!("makeCredential status 0x{:02x}", resp[0]));
    }
    let reg = rp::verify_registration(&resp[1..], "example.com", &cdh)?;
    println!(
        "register: {ms:.1} ms, hid out={} in={}, fmt={} att={} flags={} counter={} cred_id={}",
        stats.out_packets,
        stats.in_packets,
        reg.fmt,
        reg.attestation,
        rp::flags_str(reg.flags),
        reg.counter,
        ctap2::hex(&reg.cred_id)
    );
    let pk = reg.public_key.clone();
    let id = reg.cred_id.clone();
    let mut last = reg.counter;
    for round in 0..2 {
        if round == 1 {
            drop(auth);
            auth = open(dir)?;
            println!("reopened store from disk with re-derived key");
        }
        let (_, cdh) = rp::client_data("webauthn.get", "c2UtZmlkby1nZXQ", "https://example.com");
        let t = Instant::now();
        let (resp, stats) = host.transact(&mut auth, &get_req(&cdh))?;
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        if resp[0] != 0 {
            return Err(format!("getAssertion status 0x{:02x}", resp[0]));
        }
        let asr = rp::verify_assertion(&resp[1..], "example.com", &cdh, |c| {
            (c == id.as_slice()).then(|| pk.clone())
        })?;
        if asr.counter <= last {
            return Err("counter did not increase".into());
        }
        last = asr.counter;
        println!(
            "login: {ms:.1} ms, hid out={} in={}, flags={} counter={} sig=valid",
            stats.out_packets,
            stats.in_packets,
            rp::flags_str(asr.flags),
            asr.counter
        );
    }
    let resp = auth.process(&ctap2::Bytes::from(vec![0x07]), 0);
    println!("reset: status 0x{:02x}", resp[0]);
    Ok(())
}

pub fn run() -> i32 {
    let dir = tmp_root().join("se-run");
    let _ = std::fs::remove_dir_all(&dir);
    let r = run_inner(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    match r {
        Ok(()) => {
            println!("se end-to-end: PASS");
            0
        }
        Err(e) => {
            println!("se end-to-end: FAIL {e}");
            1
        }
    }
}
