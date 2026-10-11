//! se-probe: exercise the Secure Enclave from a plain CLI binary and report
//! what works.
//!
//! Usage: se-probe [--touchid] [--legacy-keychain]
//!
//!   (default)          no prompts, AccessPolicy::None
//!   --touchid          require user presence on every key use (prompts)
//!   --legacy-keychain  also try a permanent key in the legacy file keychain
//!                      (may show keychain dialogs)

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("se-probe only runs on macOS");
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
fn main() {
    probe::run();
}

#[cfg(target_os = "macos")]
mod probe {
    use backend_se::{AccessPolicy, KeyStorage, ReloadVariant, SeError, SecKey, SystemEntropy};
    use ctap2::{der, hex, Entropy};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use std::time::Instant;

    const MSG: &[u8] = b"se-fido probe message";

    fn report<T>(name: &str, r: &Result<T, SeError>) {
        match r {
            Ok(_) => println!("[ OK ] {name}"),
            Err(e) => println!("[FAIL] {name}: {e}"),
        }
    }

    fn line(ok: bool, text: &str) -> bool {
        println!("[{}] {text}", if ok { " OK " } else { "FAIL" });
        ok
    }

    fn check_sign(label: &str, key: &SecKey, pubkey: &[u8]) -> bool {
        let t = Instant::now();
        let sig = key.sign(MSG);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        report(
            &format!("{label}: SecKeyCreateSignature ({ms:.1} ms)"),
            &sig,
        );
        let Ok(sig) = sig else { return false };
        let ok = match (VerifyingKey::from_sec1_bytes(pubkey), der::decode(&sig)) {
            (Ok(vk), Some(s)) => vk.verify(MSG, &s).is_ok(),
            _ => false,
        };
        line(
            ok,
            &format!(
                "{label}: signature ({} bytes DER) verifies with p256",
                sig.len()
            ),
        )
    }

    fn check_ecdh(label: &str, key: &SecKey, se_pub: &[u8]) -> bool {
        let peer = loop {
            let mut b = [0u8; 32];
            SystemEntropy.fill(&mut b);
            if let Ok(s) = p256::SecretKey::from_slice(&b) {
                break s;
            }
        };
        let peer_pub = peer.public_key().to_encoded_point(false);
        let se_side = key.ecdh(peer_pub.as_bytes());
        report(
            &format!("{label}: SecKeyCopyKeyExchangeResult (ECDH standard)"),
            &se_side,
        );
        let Ok(se_side) = se_side else { return false };
        let Ok(se_pk) = p256::PublicKey::from_sec1_bytes(se_pub) else {
            return line(false, "bad SE public key");
        };
        let sw = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), se_pk.as_affine());
        let ok = sw.raw_secret_bytes()[..] == se_side[..];
        line(
            ok,
            &format!(
                "{label}: ECDH shared secret ({} bytes) matches software side",
                se_side.len()
            ),
        )
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let touchid = args.iter().any(|a| a == "--touchid");
        let legacy = args.iter().any(|a| a == "--legacy-keychain");
        if let Some(bad) = args
            .iter()
            .find(|a| *a != "--touchid" && *a != "--legacy-keychain")
        {
            eprintln!("unknown argument {bad}");
            std::process::exit(2);
        }
        let policy = if touchid {
            AccessPolicy::UserPresence
        } else {
            AccessPolicy::None
        };
        println!("se-probe: policy={policy:?}");
        let mut all_ok = true;

        println!("\n== mode b: ephemeral key + toid blob ==");
        let t = Instant::now();
        let key = SecKey::generate(&KeyStorage::Ephemeral, policy);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        report(
            &format!("SecKeyCreateRandomKey(tokenID=SecureEnclave, permanent=false) ({ms:.1} ms)"),
            &key,
        );
        match key {
            Err(_) => all_ok = false,
            Ok(key) => {
                let pubkey = key.public_key_sec1();
                report("public key export", &pubkey);
                let pubkey = pubkey.unwrap_or_default();
                println!(
                    "       public key ({} bytes): {}",
                    pubkey.len(),
                    hex(&pubkey)
                );
                all_ok &= check_sign("fresh key", &key, &pubkey);
                println!("       attributes:");
                for (k, v) in key.attribute_summary() {
                    println!("         {k} = {v}");
                }
                let blob = key.token_object_blob();
                report("read toid token object blob", &blob);
                match blob {
                    Err(_) => all_ok = false,
                    Ok(blob) => {
                        println!("       BLOB SIZE: {} bytes", blob.len());
                        drop(key);
                        let mut usable = false;
                        for v in ReloadVariant::ALL {
                            let t = Instant::now();
                            let k = SecKey::from_blob(&blob, v);
                            let ms = t.elapsed().as_secs_f64() * 1000.0;
                            report(&format!("reload {v:?} ({ms:.1} ms)"), &k);
                            let Ok(k) = k else { continue };
                            let same = k.public_key_sec1().map(|p| p == pubkey).unwrap_or(false);
                            line(same, &format!("{v:?}: reloaded public key matches"));
                            let signed = check_sign(&format!("reloaded {v:?}"), &k, &pubkey);
                            if same && signed && !usable {
                                usable = true;
                                all_ok &= check_ecdh(&format!("reloaded {v:?}"), &k, &pubkey);
                            }
                        }
                        all_ok &= line(usable, "at least one reload variant returns the same key");
                    }
                }
            }
        }

        let mut variants = vec![(true, "data-protection keychain")];
        if legacy {
            variants.push((false, "legacy file keychain"));
        }
        for (dp, name) in variants {
            println!("\n== mode a: permanent key, {name} ==");
            let mut rnd = [0u8; 8];
            SystemEntropy.fill(&mut rnd);
            let mut tag = b"se-fido:probe:".to_vec();
            tag.extend_from_slice(hex(&rnd).as_bytes());
            let k = SecKey::generate(
                &KeyStorage::Keychain {
                    tag: tag.clone(),
                    data_protection: dp,
                },
                policy,
            );
            report("SecKeyCreateRandomKey(permanent=true, applicationTag)", &k);
            let Ok(k) = k else { continue };
            let pubkey = k.public_key_sec1().unwrap_or_default();
            drop(k);
            let found = SecKey::find_in_keychain(&tag, dp);
            report("SecItemCopyMatching by tag", &found);
            if let Ok(found) = found {
                check_sign("keychain key", &found, &pubkey);
            }
            report(
                "SecItemDelete (cleanup)",
                &SecKey::delete_from_keychain(&tag, dp),
            );
            line(
                SecKey::find_in_keychain(&tag, dp).is_err(),
                "key gone after delete",
            );
        }

        println!(
            "\nsummary: blob mode {}",
            if all_ok { "WORKS" } else { "HAS FAILURES" }
        );
        if !all_ok {
            std::process::exit(1);
        }
    }
}
