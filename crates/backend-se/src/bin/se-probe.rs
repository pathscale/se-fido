//! se-probe: exercise the Secure Enclave from a plain CLI binary and report
//! exactly what works.
//!
//! Usage: se-probe [--touchid] [--legacy-keychain]
//!
//!   (default)          no user prompts: AccessPolicy::None
//!   --touchid          require user presence (Touch ID / password) on every
//!                      private-key use; expect prompts
//!   --legacy-keychain  also try a permanent key in the legacy file keychain
//!                      (may show keychain dialogs; off by default)

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
    use backend_se::{AccessPolicy, KeyStorage, ReloadVariant, SeError, SecKey};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use rand::RngCore;

    const MSG: &[u8] = b"se-fido probe message";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn report<T>(name: &str, r: &Result<T, SeError>) {
        match r {
            Ok(_) => println!("[ OK ] {name}"),
            Err(e) => println!("[FAIL] {name}: {e}"),
        }
    }

    fn verify(pubkey: &[u8], sig: &[u8]) -> Result<(), String> {
        let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|e| format!("bad pubkey: {e}"))?;
        let s = Signature::from_der(sig).map_err(|e| format!("bad DER: {e}"))?;
        vk.verify(MSG, &s)
            .map_err(|e| format!("verify failed: {e}"))
    }

    fn check_sign(label: &str, key: &SecKey, pubkey: &[u8]) -> bool {
        let sig = key.sign(MSG);
        report(&format!("{label}: SecKeyCreateSignature"), &sig);
        let Ok(sig) = sig else { return false };
        match verify(pubkey, &sig) {
            Ok(()) => {
                println!(
                    "[ OK ] {label}: signature ({} bytes DER) verifies with p256",
                    sig.len()
                );
                true
            }
            Err(e) => {
                println!("[FAIL] {label}: {e}");
                false
            }
        }
    }

    fn check_ecdh(label: &str, key: &SecKey, se_pub: &[u8]) -> bool {
        let peer = p256::SecretKey::random(&mut OsRng);
        let peer_pub = peer.public_key().to_encoded_point(false);
        let se_side = key.ecdh(peer_pub.as_bytes());
        report(
            &format!("{label}: SecKeyCopyKeyExchangeResult (ECDH standard)"),
            &se_side,
        );
        let Ok(se_side) = se_side else { return false };
        let se_pk = p256::PublicKey::from_sec1_bytes(se_pub).expect("checked earlier");
        let sw = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), se_pk.as_affine());
        let ok = sw.raw_secret_bytes()[..] == se_side[..];
        println!(
            "[{}] {label}: ECDH shared secret ({} bytes) {} software side",
            if ok { " OK " } else { "FAIL" },
            se_side.len(),
            if ok { "matches" } else { "DOES NOT match" }
        );
        ok
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

        // ---- Mode (b): non-permanent key + token-object blob ----
        println!("\n== mode b: ephemeral key + 'toid' blob ==");
        let key = SecKey::generate(&KeyStorage::Ephemeral, policy);
        report(
            "SecKeyCreateRandomKey(tokenID=SecureEnclave, permanent=false)",
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
                report("read 'toid' token object blob", &blob);
                match blob {
                    Err(_) => all_ok = false,
                    Ok(blob) => {
                        println!("       BLOB SIZE: {} bytes", blob.len());
                        drop(key);
                        let mut any = false;
                        for v in ReloadVariant::ALL {
                            let k = SecKey::from_blob(&blob, v);
                            report(&format!("reload via SecKeyCreateWithData {v:?}"), &k);
                            if let Ok(k) = k {
                                let same =
                                    k.public_key_sec1().map(|p| p == pubkey).unwrap_or(false);
                                println!(
                                    "[{}] {v:?}: reloaded public key matches",
                                    if same { " OK " } else { "FAIL" }
                                );
                                let signed = check_sign(&format!("reloaded {v:?}"), &k, &pubkey);
                                if same && signed && !any {
                                    any = true;
                                    all_ok &= check_ecdh(&format!("reloaded {v:?}"), &k, &pubkey);
                                }
                            }
                        }
                        if !any {
                            all_ok = false;
                            println!("[FAIL] no reload variant worked");
                        }
                    }
                }
            }
        }

        // ---- Mode (a): permanent keychain item ----
        let mut variants = vec![(true, "data-protection keychain")];
        if legacy {
            variants.push((false, "legacy file keychain"));
        }
        for (dp, name) in variants {
            println!("\n== mode a: permanent key, {name} ==");
            let mut tag = b"se-fido:probe:".to_vec();
            let mut rnd = [0u8; 8];
            OsRng.fill_bytes(&mut rnd);
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
            let del = SecKey::delete_from_keychain(&tag, dp);
            report("SecItemDelete (cleanup)", &del);
            let gone = SecKey::find_in_keychain(&tag, dp);
            println!(
                "[{}] key gone after delete",
                if gone.is_err() { " OK " } else { "FAIL" }
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
