//! Persistence round trip: insert a credential, reopen the store with the
//! same key and read it back.

use ctap2::{Bytes, Credential, CredentialStore, TestDrbg, Text, UvPolicy};
use se_fido_store::FileStore;
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
    let directory = std::env::temp_dir().join(format!("store-roundtrip-{}", std::process::id()));
    fs::create_dir(&directory).expect("create isolated example directory");
    let scratch = Scratch(directory);
    let key = [7; 32];
    let mut store =
        FileStore::open(&scratch.0, &key, TestDrbg::new([8; 32])).expect("open example store");
    store
        .insert(credential(1, b"ordinary"))
        .expect("persist credential");
    drop(store);
    let reopened =
        FileStore::open(&scratch.0, &key, TestDrbg::new([9; 32])).expect("reopen example store");
    assert_eq!(reopened.len(), 1);
    assert_eq!(
        reopened
            .get(&[1])
            .expect("read credential")
            .expect("credential present")
            .user_id
            .as_ref(),
        b"ordinary"
    );
    println!("credential persisted and reloaded");
}
