use crate::authdata::{self, AttestedCredential, FLAG_UP, FLAG_UV};
use crate::bytes::{Bytes, Text};
use crate::cbor::{decode, encode, Out, Value};
use crate::der;
use crate::types::*;
use crate::{command, Status, AAGUID, COSE_ALG_ES256};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationFormat {
    /// "packed" self attestation: signed by the credential key, no x5c.
    PackedSelf,
    /// "none": empty statement.
    None,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    pub aaguid: [u8; 16],
    pub attestation: AttestationFormat,
    /// Advertise and perform built-in user verification (Touch ID).
    pub builtin_uv: bool,
    /// maxMsgSize in GetInfo (CTAPHID maximum by default).
    pub max_msg_size: u32,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        AuthenticatorConfig {
            aaguid: AAGUID,
            attestation: AttestationFormat::PackedSelf,
            builtin_uv: true,
            max_msg_size: 7609,
        }
    }
}

/// GetNextAssertion state lifetime (spec: 30 s).
pub const NEXT_ASSERTION_TIMEOUT_MS: u64 = 30_000;
const MAX_USER_ID_LEN: usize = 64;
/// Names are truncated to this many bytes (allowed by the spec).
const MAX_NAME_LEN: usize = 64;

struct Pending {
    rp_id: Text,
    client_data_hash: Bytes,
    flags: u8,
    user_verified: bool,
    remaining: Vec<Arc<Credential>>,
    started_ms: u64,
}

/// The CTAP2 authenticator state machine.
pub struct Authenticator<B, S, P> {
    backend: B,
    store: S,
    presence: P,
    config: AuthenticatorConfig,
    pending: Option<Pending>,
}

#[derive(Default)]
struct Options {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
}

fn parse_options(v: Option<&Value>) -> Result<Options, Status> {
    let mut o = Options::default();
    let Some(v) = v else { return Ok(o) };
    for (k, val) in v.as_map()? {
        let Value::Text(k) = k else { continue };
        match k.as_str() {
            "rk" => o.rk = Some(val.as_bool()?),
            "up" => o.up = Some(val.as_bool()?),
            "uv" => o.uv = Some(val.as_bool()?),
            _ => {}
        }
    }
    Ok(o)
}

/// IDs of "public-key" descriptors; other types are skipped.
fn parse_descriptors(v: &Value) -> Result<Vec<Bytes>, Status> {
    let mut ids = Vec::new();
    for d in v.as_array()? {
        d.as_map()?;
        let ty = d
            .get_text("type")
            .ok_or(Status::MissingParameter)?
            .as_text()?;
        let id = d
            .get_text("id")
            .ok_or(Status::MissingParameter)?
            .as_bytes()?;
        if ty.as_str() == "public-key" {
            ids.push(id.clone());
        }
    }
    Ok(ids)
}

fn optional_text(m: &Value, key: &str) -> Result<Option<Text>, Status> {
    match m.get_text(key) {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_text()?.truncated(MAX_NAME_LEN))),
    }
}

fn required_map(v: Option<&Value>) -> Result<&Value, Status> {
    let v = v.ok_or(Status::MissingParameter)?;
    v.as_map()?;
    Ok(v)
}

fn store_err(e: StoreError) -> Status {
    match e {
        StoreError::Full => Status::KeyStoreFull,
        _ => Status::Other,
    }
}

fn backend_err(e: BackendError) -> Status {
    match e {
        BackendError::KeyNotFound => Status::InvalidCredential,
        BackendError::Cancelled => Status::OperationDenied,
        BackendError::Failed(_) => Status::Other,
    }
}

impl<B: Backend, S: CredentialStore, P: UserPresence> Authenticator<B, S, P> {
    pub fn new(backend: B, store: S, presence: P, config: AuthenticatorConfig) -> Self {
        Authenticator {
            backend,
            store,
            presence,
            config,
            pending: None,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn presence(&self) -> &P {
        &self.presence
    }
    pub fn presence_mut(&mut self) -> &mut P {
        &mut self.presence
    }
    pub fn config(&self) -> &AuthenticatorConfig {
        &self.config
    }

    /// Handle one request (command byte + CBOR); returns status + CBOR.
    pub fn process(&mut self, request: &Bytes, now_ms: u64) -> Vec<u8> {
        match self.dispatch(request, now_ms) {
            Ok(body) => {
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(Status::Ok.code());
                out.extend_from_slice(&body);
                out
            }
            Err(s) => vec![s.code()],
        }
    }

    fn dispatch(&mut self, request: &Bytes, now_ms: u64) -> Result<Vec<u8>, Status> {
        let &cmd = request.first().ok_or(Status::InvalidLength)?;
        let params = request
            .slice(1..request.len())
            .ok_or(Status::InvalidLength)?;
        if cmd != command::GET_NEXT_ASSERTION {
            self.pending = None;
        }
        match cmd {
            command::GET_INFO => Ok(self.get_info()),
            command::MAKE_CREDENTIAL => self.make_credential(&parse_params(&params)?),
            command::GET_ASSERTION => self.get_assertion(&parse_params(&params)?, now_ms),
            command::GET_NEXT_ASSERTION => self.get_next_assertion(now_ms),
            command::RESET => self.reset().map(|_| Vec::new()),
            command::SELECTION => self
                .ask(PresenceKind::Selection, None, None, false)
                .map(|_| Vec::new()),
            // clientPin and anything else: not implemented.
            _ => Err(Status::InvalidCommand),
        }
    }

    fn get_info(&self) -> Vec<u8> {
        let mut options = vec![
            (Out::Text("rk"), Out::Bool(true)),
            (Out::Text("up"), Out::Bool(true)),
            (Out::Text("plat"), Out::Bool(false)),
        ];
        if self.config.builtin_uv {
            options.push((Out::Text("uv"), Out::Bool(true)));
        }
        encode(&Out::Map(vec![
            (Out::Int(0x01), Out::Array(vec![Out::Text("FIDO_2_0")])),
            (Out::Int(0x03), Out::Bytes(&self.config.aaguid)),
            (Out::Int(0x04), Out::Map(options)),
            (Out::Int(0x05), Out::Int(self.config.max_msg_size as i64)),
            (Out::Int(0x09), Out::Array(vec![Out::Text("usb")])),
            (
                Out::Int(0x0a),
                Out::Array(vec![Out::Map(vec![
                    (Out::Text("alg"), Out::Int(COSE_ALG_ES256)),
                    (Out::Text("type"), Out::Text("public-key")),
                ])]),
            ),
        ]))
    }

    fn ask(
        &mut self,
        kind: PresenceKind,
        rp_id: Option<&Text>,
        user_name: Option<&Text>,
        require_uv: bool,
    ) -> Result<Presence, Status> {
        let req = PresenceRequest {
            kind,
            rp_id: rp_id.cloned(),
            user_name: user_name.cloned(),
            require_uv,
        };
        let p = self.presence.request(&req).map_err(|e| match e {
            PresenceError::Denied | PresenceError::UvFailed => Status::OperationDenied,
            PresenceError::Cancelled => Status::KeepaliveCancel,
            PresenceError::Timeout => Status::UserActionTimeout,
        })?;
        if require_uv && !p.user_verified {
            return Err(Status::OperationDenied);
        }
        Ok(p)
    }

    /// No PIN/UV auth protocol is implemented. A zero-length pinUvAuthParam
    /// (platform "touch to select" probe) collects presence then answers
    /// PIN_NOT_SET; any other value is rejected.
    fn pin_uv_auth(
        &mut self,
        m: &Value,
        param_key: i64,
        proto_key: i64,
        rp_id: &Text,
    ) -> Result<(), Status> {
        let Some(p) = m.get(param_key) else {
            return Ok(());
        };
        if p.as_bytes()?.is_empty() {
            self.ask(PresenceKind::Probe, Some(rp_id), None, false)?;
            return Err(Status::PinNotSet);
        }
        if m.get(proto_key).is_none() {
            return Err(Status::MissingParameter);
        }
        Err(Status::InvalidParameter)
    }

    /// Sign and verify against the stored public key before releasing.
    fn sign_checked(&mut self, cred: &Credential, msg: &[u8]) -> Result<Vec<u8>, Status> {
        let sig = self
            .backend
            .sign(&cred.key_handle, msg)
            .map_err(backend_err)?;
        let vk = VerifyingKey::from_sec1_bytes(&cred.public_key).map_err(|_| Status::Other)?;
        let parsed = der::decode(&sig).ok_or(Status::Other)?;
        vk.verify(msg, &parsed).map_err(|_| Status::Other)?;
        Ok(sig)
    }

    fn make_credential(&mut self, m: &Value) -> Result<Vec<u8>, Status> {
        let client_data_hash = m
            .get(0x01)
            .ok_or(Status::MissingParameter)?
            .as_bytes()?
            .clone();
        let rp = required_map(m.get(0x02))?;
        let rp_id = rp
            .get_text("id")
            .ok_or(Status::MissingParameter)?
            .as_text()?
            .clone();
        let rp_name = optional_text(rp, "name")?;
        let user = required_map(m.get(0x03))?;
        let user_id = user
            .get_text("id")
            .ok_or(Status::MissingParameter)?
            .as_bytes()?
            .clone();
        let user_name = optional_text(user, "name")?;
        let user_display_name = optional_text(user, "displayName")?;
        let cred_params = m.get(0x04).ok_or(Status::MissingParameter)?.as_array()?;

        self.pin_uv_auth(m, 0x08, 0x09, &rp_id)?;

        if user_id.len() > MAX_USER_ID_LEN {
            return Err(Status::InvalidLength);
        }
        let mut es256 = false;
        for p in cred_params {
            p.as_map()?;
            let ty = p
                .get_text("type")
                .ok_or(Status::MissingParameter)?
                .as_text()?;
            let alg = p
                .get_text("alg")
                .ok_or(Status::MissingParameter)?
                .as_int()?;
            if ty.as_str() == "public-key" && alg == COSE_ALG_ES256 as i128 {
                es256 = true;
            }
        }
        if !es256 {
            return Err(Status::UnsupportedAlgorithm);
        }
        let exclude = match m.get(0x05) {
            Some(v) => parse_descriptors(v)?,
            None => Vec::new(),
        };
        if let Some(ext) = m.get(0x06) {
            ext.as_map()?; // no extensions supported, but must be a map
        }
        let opts = parse_options(m.get(0x07))?;
        if m.get(0x0a).is_some() {
            return Err(Status::InvalidParameter); // enterprise attestation
        }
        if opts.up == Some(false) {
            return Err(Status::InvalidOption);
        }
        let want_uv = opts.uv == Some(true);
        if want_uv && !self.config.builtin_uv {
            return Err(Status::UnsupportedOption);
        }
        let rk = opts.rk == Some(true);

        for id in &exclude {
            let hit = self
                .store
                .get(id)
                .map_err(store_err)?
                .is_some_and(|c| c.rp_id == rp_id);
            if hit {
                if let Err(Status::KeepaliveCancel) =
                    self.ask(PresenceKind::Excluded, Some(&rp_id), None, false)
                {
                    return Err(Status::KeepaliveCancel);
                }
                return Err(Status::CredentialExcluded);
            }
        }

        let presence = self.ask(
            PresenceKind::MakeCredential,
            Some(&rp_id),
            user_name.as_ref(),
            want_uv,
        )?;
        let mut flags = FLAG_UP;
        if presence.user_verified {
            flags |= FLAG_UV;
        }

        let key = self
            .backend
            .create_key(rp_id.as_str(), &user_id)
            .map_err(backend_err)?;
        let mut cred_id = [0u8; CREDENTIAL_ID_LEN];
        self.backend.random(&mut cred_id);
        let counter = match self.store.next_sign_count() {
            Ok(c) => c,
            Err(e) => {
                let _ = self.backend.delete_key(&key.handle);
                return Err(store_err(e));
            }
        };
        let cred = Arc::new(Credential {
            id: Bytes::copy_from_slice(&cred_id),
            rp_id: rp_id.clone(),
            rp_name,
            user_id: user_id.clone(),
            user_name,
            user_display_name,
            key_handle: key.handle.clone(),
            public_key: Bytes::copy_from_slice(key.public_key.to_encoded_point(false).as_bytes()),
            discoverable: rk,
            created: counter as u64,
        });

        let cose = authdata::cose_key(&key.public_key);
        let auth_data = authdata::build(
            rp_id.as_str(),
            flags,
            counter,
            Some(&AttestedCredential {
                aaguid: &self.config.aaguid,
                credential_id: &cred_id,
                cose_key: &cose,
            }),
            None,
        );
        let sig = match self.config.attestation {
            AttestationFormat::None => None,
            AttestationFormat::PackedSelf => {
                let mut msg = auth_data.clone();
                msg.extend_from_slice(&client_data_hash);
                match self.sign_checked(&cred, &msg) {
                    Ok(sig) => Some(sig),
                    Err(e) => {
                        let _ = self.backend.delete_key(&key.handle);
                        return Err(e);
                    }
                }
            }
        };

        // A resident credential for the same RP and user replaces the old one.
        let replaced: Vec<Arc<Credential>> = if rk {
            self.store
                .list_rp(rp_id.as_str())
                .map_err(store_err)?
                .into_iter()
                .filter(|c| c.discoverable && c.user_id == user_id)
                .collect()
        } else {
            Vec::new()
        };
        if let Err(e) = self.store.insert(cred) {
            let _ = self.backend.delete_key(&key.handle);
            return Err(store_err(e));
        }
        for old in replaced {
            let _ = self.store.remove(&old.id);
            let _ = self.backend.delete_key(&old.key_handle);
        }

        let (fmt, att_stmt) = match &sig {
            None => ("none", Out::Map(Vec::new())),
            Some(sig) => (
                "packed",
                Out::Map(vec![
                    (Out::Text("alg"), Out::Int(COSE_ALG_ES256)),
                    (Out::Text("sig"), Out::Bytes(sig)),
                ]),
            ),
        };
        Ok(encode(&Out::Map(vec![
            (Out::Int(0x01), Out::Text(fmt)),
            (Out::Int(0x02), Out::Bytes(&auth_data)),
            (Out::Int(0x03), att_stmt),
        ])))
    }

    fn assertion(
        &mut self,
        rp_id: &Text,
        client_data_hash: &[u8],
        flags: u8,
        user_verified: bool,
        cred: &Credential,
        total: Option<usize>,
    ) -> Result<Vec<u8>, Status> {
        let counter = self.store.next_sign_count().map_err(store_err)?;
        let auth_data = authdata::build(rp_id.as_str(), flags, counter, None, None);
        let mut msg = auth_data.clone();
        msg.extend_from_slice(client_data_hash);
        let sig = self.sign_checked(cred, &msg)?;
        let mut entries = vec![
            (
                Out::Int(0x01),
                Out::Map(vec![
                    (Out::Text("id"), Out::Bytes(&cred.id)),
                    (Out::Text("type"), Out::Text("public-key")),
                ]),
            ),
            (Out::Int(0x02), Out::Bytes(&auth_data)),
            (Out::Int(0x03), Out::Bytes(&sig)),
        ];
        if cred.discoverable {
            let mut user = vec![(Out::Text("id"), Out::Bytes(&cred.user_id))];
            // Identifying information only after user verification.
            if user_verified {
                if let Some(n) = &cred.user_name {
                    user.push((Out::Text("name"), Out::Text(n.as_str())));
                }
                if let Some(n) = &cred.user_display_name {
                    user.push((Out::Text("displayName"), Out::Text(n.as_str())));
                }
            }
            entries.push((Out::Int(0x04), Out::Map(user)));
        }
        if let Some(n) = total {
            entries.push((Out::Int(0x05), Out::Int(n as i64)));
        }
        Ok(encode(&Out::Map(entries)))
    }

    fn get_assertion(&mut self, m: &Value, now_ms: u64) -> Result<Vec<u8>, Status> {
        let rp_id = m
            .get(0x01)
            .ok_or(Status::MissingParameter)?
            .as_text()?
            .clone();
        let client_data_hash = m
            .get(0x02)
            .ok_or(Status::MissingParameter)?
            .as_bytes()?
            .clone();
        self.pin_uv_auth(m, 0x06, 0x07, &rp_id)?;
        let allow = match m.get(0x03) {
            Some(v) => parse_descriptors(v)?,
            None => Vec::new(),
        };
        if let Some(ext) = m.get(0x04) {
            ext.as_map()?;
        }
        let opts = parse_options(m.get(0x05))?;
        if opts.rk.is_some() {
            return Err(Status::UnsupportedOption);
        }
        let want_up = opts.up.unwrap_or(true);
        let want_uv = opts.uv == Some(true);
        if want_uv && !self.config.builtin_uv {
            return Err(Status::UnsupportedOption);
        }

        let using_allow_list = !allow.is_empty();
        let mut creds: Vec<Arc<Credential>> = Vec::new();
        if using_allow_list {
            for id in &allow {
                if let Some(c) = self.store.get(id).map_err(store_err)? {
                    if c.rp_id == rp_id && !creds.iter().any(|x| x.id == c.id) {
                        creds.push(c);
                    }
                }
            }
        } else {
            creds = self
                .store
                .list_rp(rp_id.as_str())
                .map_err(store_err)?
                .into_iter()
                .filter(|c| c.discoverable)
                .collect();
            creds.sort_by_key(|c| core::cmp::Reverse(c.created));
        }

        let mut flags = 0u8;
        let mut user_verified = false;
        if want_up || want_uv {
            // Presence is collected even if nothing matches, so sites cannot
            // silently probe for credentials.
            let p = self.ask(PresenceKind::GetAssertion, Some(&rp_id), None, want_uv)?;
            if want_up {
                flags |= FLAG_UP;
            }
            if p.user_verified {
                flags |= FLAG_UV;
                user_verified = true;
            }
        }
        if creds.is_empty() {
            return Err(Status::NoCredentials);
        }
        let first = creds.remove(0);
        let total = if !using_allow_list && !creds.is_empty() {
            Some(creds.len() + 1)
        } else {
            None
        };
        let out = self.assertion(
            &rp_id,
            &client_data_hash,
            flags,
            user_verified,
            &first,
            total,
        )?;
        if total.is_some() {
            self.pending = Some(Pending {
                rp_id,
                client_data_hash,
                flags,
                user_verified,
                remaining: creds,
                started_ms: now_ms,
            });
        }
        Ok(out)
    }

    fn get_next_assertion(&mut self, now_ms: u64) -> Result<Vec<u8>, Status> {
        let mut p = self.pending.take().ok_or(Status::NotAllowed)?;
        if now_ms.saturating_sub(p.started_ms) > NEXT_ASSERTION_TIMEOUT_MS || p.remaining.is_empty()
        {
            return Err(Status::NotAllowed);
        }
        let cred = p.remaining.remove(0);
        let out = self.assertion(
            &p.rp_id,
            &p.client_data_hash,
            p.flags,
            p.user_verified,
            &cred,
            None,
        )?;
        if !p.remaining.is_empty() {
            p.started_ms = now_ms;
            self.pending = Some(p);
        }
        Ok(out)
    }

    fn reset(&mut self) -> Result<(), Status> {
        self.ask(PresenceKind::Reset, None, None, false)?;
        for c in self.store.clear().map_err(store_err)? {
            let _ = self.backend.delete_key(&c.key_handle);
        }
        Ok(())
    }
}

fn parse_params(params: &Bytes) -> Result<Value, Status> {
    if params.is_empty() {
        return Err(Status::MissingParameter);
    }
    let v = decode(params)?;
    v.as_map()?;
    Ok(v)
}
