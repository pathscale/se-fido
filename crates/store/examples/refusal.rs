//! Executable persistence witness using a synthetic token supplied by its caller.

use ctap2::{Bytes, Credential, CredentialStore, TestDrbg, Text, UvPolicy};
use se_fido_store::{check_environment_secrets, FileStore, CRED_FILE};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn credential(id: u8, user: &[u8]) -> Arc<Credential> {
    Arc::new(Credential {
        id: Bytes::copy_from_slice(&[id]),
        rp_id: Text::from("example.invalid"),
        rp_name: None,
        user_id: Bytes::copy_from_slice(user),
        user_name: None,
        user_display_name: None,
        key_handle: Bytes::copy_from_slice(b"opaque-reference"),
        public_key: Bytes::copy_from_slice(&[4; 65]),
        discoverable: false,
        created: 0,
        uv_policy: UvPolicy::None,
    })
}

fn main() {
    let token = std::env::var_os("STORE_WITNESS_TOKEN").expect("supply a synthetic witness token");
    let token = token.as_encoded_bytes();
    assert!(!token.is_empty());
    assert!(check_environment_secrets(token).is_err());
    let directory = std::env::temp_dir().join(format!("store-refusal-{}", std::process::id()));
    fs::create_dir(&directory).expect("create isolated witness directory");
    let scratch = Scratch(directory);
    let key = [7; 32];
    let mut store =
        FileStore::open(&scratch.0, &key, TestDrbg::new([8; 32])).expect("open witness store");
    store
        .insert(credential(1, b"ordinary"))
        .expect("persist ordinary credential");
    let original = fs::read(scratch.0.join(CRED_FILE)).expect("read original ciphertext");
    assert!(
        store.insert(credential(1, token)).is_err(),
        "refuse replacement"
    );
    assert!(
        store.insert(credential(2, token)).is_err(),
        "refuse new credential"
    );
    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .get(&[1])
            .expect("read live credential")
            .expect("existing credential")
            .user_id
            .as_ref(),
        b"ordinary"
    );
    assert!(store.get(&[2]).expect("read rejected credential").is_none());
    assert_eq!(
        fs::read(scratch.0.join(CRED_FILE)).expect("read preserved ciphertext"),
        original
    );
    assert!(!scratch.0.join(format!(".{CRED_FILE}.tmp")).exists());
    drop(store);
    let mut reopened =
        FileStore::open(&scratch.0, &key, TestDrbg::new([9; 32])).expect("reopen preserved store");
    assert_eq!(reopened.len(), 1);
    reopened
        .insert(credential(2, b"ordinary"))
        .expect("valid write after refusal");
    println!(
        "plaintext refusal preserved live and durable credentials; subsequent write succeeded"
    );
}
