use crate::authdata::{self, AttestedCredential, FLAG_UP, FLAG_UV};
use crate::cbor::{
    as_array, as_bool, as_bytes, as_int, as_text, bytes, decode, int, text, to_canonical_vec,
    MapView,
};
use crate::types::*;
use crate::{command, Status, AAGUID, COSE_ALG_ES256};
use ciborium::value::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

/// Attestation statement format returned by authenticatorMakeCredential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationFormat {
    /// "packed" self attestation: signed with the credential's own key, no
    /// certificate chain (WebAuthn section 8.2, self attestation).
    PackedSelf,
    /// "none": empty attestation statement.
    None,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    pub aaguid: [u8; 16],
    pub attestation: AttestationFormat,
    /// Advertise and perform built-in user verification (Touch ID). When
    /// true, GetInfo reports `options.uv = true` and requests with
    /// `options.uv = true` require [`Presence::user_verified`].
    pub builtin_uv: bool,
    /// Value reported as maxMsgSize in GetInfo (CTAPHID maximum by default).
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

/// Spec: authenticatorGetNextAssertion state expires after 30 seconds.
const NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_USER_ID_LEN: usize = 64;
/// Names longer than this are truncated (spec permits truncation to 64 bytes).
const MAX_NAME_LEN: usize = 64;

struct PendingAssertions {
    rp_id: String,
    client_data_hash: Vec<u8>,
    flags: u8,
    user_verified: bool,
    remaining: Vec<Credential>,
    started: Instant,
}

/// The CTAP2 authenticator state machine.
pub struct Authenticator<B, S, P> {
    backend: B,
    store: S,
    presence: P,
    config: AuthenticatorConfig,
    pending: Option<PendingAssertions>,
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
    let m = MapView::from_value(v)?;
    for (k, val) in m.0 {
        let Value::Text(k) = k else { continue };
        match k.as_str() {
            "rk" => o.rk = Some(as_bool(val)?),
            "up" => o.up = Some(as_bool(val)?),
            "uv" => o.uv = Some(as_bool(val)?),
            _ => {} // unknown options are ignored
        }
    }
    Ok(o)
}

/// Parse a list of PublicKeyCredentialDescriptors, keeping IDs of type
/// "public-key" and ignoring other types.
fn parse_descriptors(v: &Value) -> Result<Vec<Vec<u8>>, Status> {
    let mut ids = Vec::new();
    for d in as_array(v)? {
        let dm = MapView::from_value(d)?;
        let ty = as_text(dm.get_text_key("type").ok_or(Status::MissingParameter)?)?;
        let id = as_bytes(dm.get_text_key("id").ok_or(Status::MissingParameter)?)?;
        if ty == "public-key" {
            ids.push(id.to_vec());
        }
    }
    Ok(ids)
}

fn optional_text(m: &MapView<'_>, key: &str) -> Result<Option<String>, Status> {
    match m.get_text_key(key) {
        None => Ok(None),
        Some(v) => Ok(Some(truncate(as_text(v)?))),
    }
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_NAME_LEN {
        return s.to_owned();
    }
    let mut end = MAX_NAME_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn parse_params(params: &[u8]) -> Result<Value, Status> {
    if params.is_empty() {
        return Err(Status::MissingParameter);
    }
    let v = decode(params)?;
    match v {
        Value::Map(_) => Ok(v),
        _ => Err(Status::CborUnexpectedType),
    }
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
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
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

    /// Handle one CTAP2 request (command byte followed by CBOR parameters)
    /// and return the response (status byte followed by optional CBOR).
    pub fn process(&mut self, request: &[u8]) -> Vec<u8> {
        match self.dispatch(request) {
            Ok(Some(v)) => {
                let mut out = vec![Status::Ok.code()];
                out.extend(to_canonical_vec(v));
                out
            }
            Ok(None) => vec![Status::Ok.code()],
            Err(s) => vec![s.code()],
        }
    }

    fn dispatch(&mut self, request: &[u8]) -> Result<Option<Value>, Status> {
        let (&cmd, params) = request.split_first().ok_or(Status::InvalidLength)?;
        if cmd != command::GET_NEXT_ASSERTION {
            self.pending = None;
        }
        match cmd {
            command::GET_INFO => Ok(Some(self.get_info())),
            command::MAKE_CREDENTIAL => self.make_credential(&parse_params(params)?).map(Some),
            command::GET_ASSERTION => self.get_assertion(&parse_params(params)?).map(Some),
            command::GET_NEXT_ASSERTION => self.get_next_assertion().map(Some),
            command::RESET => self.reset().map(|_| None),
            command::SELECTION => self
                .ask(PresenceKind::Selection, None, None, false)
                .map(|_| None),
            // clientPin is not implemented (see README); fall through.
            _ => Err(Status::InvalidCommand),
        }
    }

    fn get_info(&self) -> Value {
        let mut options = vec![
            (text("rk"), Value::Bool(true)),
            (text("up"), Value::Bool(true)),
            (text("plat"), Value::Bool(false)),
        ];
        if self.config.builtin_uv {
            options.push((text("uv"), Value::Bool(true)));
        }
        Value::Map(vec![
            (int(0x01), Value::Array(vec![text("FIDO_2_0")])),
            (int(0x03), bytes(&self.config.aaguid)),
            (int(0x04), Value::Map(options)),
            (int(0x05), int(self.config.max_msg_size as i64)),
            (int(0x09), Value::Array(vec![text("usb")])),
            (
                int(0x0a),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(COSE_ALG_ES256)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ])
    }

    fn ask(
        &mut self,
        kind: PresenceKind,
        rp_id: Option<&str>,
        user_name: Option<&str>,
        require_uv: bool,
    ) -> Result<Presence, Status> {
        let req = PresenceRequest {
            kind,
            rp_id: rp_id.map(str::to_owned),
            user_name: user_name.map(str::to_owned),
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

    /// Handle pinUvAuthParam / pinUvAuthProtocol. No PIN/UV auth protocol is
    /// implemented, so a zero-length parameter (the platform's "touch to
    /// select this authenticator" probe) collects presence and answers
    /// PIN_NOT_SET, and any other value is rejected.
    fn pin_uv_auth(
        &mut self,
        m: &MapView<'_>,
        param_key: i64,
        proto_key: i64,
        rp_id: Option<&str>,
    ) -> Result<(), Status> {
        let Some(p) = m.get_int_key(param_key) else {
            return Ok(());
        };
        let p = as_bytes(p)?;
        if p.is_empty() {
            self.ask(PresenceKind::Probe, rp_id, None, false)?;
            return Err(Status::PinNotSet);
        }
        if m.get_int_key(proto_key).is_none() {
            return Err(Status::MissingParameter);
        }
        Err(Status::InvalidParameter)
    }

    fn sign_checked(&mut self, cred: &Credential, msg: &[u8]) -> Result<Vec<u8>, Status> {
        let sig = self
            .backend
            .sign(&cred.key_handle, msg)
            .map_err(backend_err)?;
        // Defence in depth: never emit a signature that does not verify
        // against the public key we gave the relying party.
        let vk = VerifyingKey::from_sec1_bytes(&cred.public_key).map_err(|_| Status::Other)?;
        let parsed = Signature::from_der(&sig).map_err(|_| Status::Other)?;
        vk.verify(msg, &parsed).map_err(|_| Status::Other)?;
        Ok(sig)
    }

    fn make_credential(&mut self, params: &Value) -> Result<Value, Status> {
        let m = MapView::from_value(params)?;
        let client_data_hash =
            as_bytes(m.get_int_key(0x01).ok_or(Status::MissingParameter)?)?.to_vec();
        let rp = MapView::from_value(m.get_int_key(0x02).ok_or(Status::MissingParameter)?)?;
        let rp_id = as_text(rp.get_text_key("id").ok_or(Status::MissingParameter)?)?.to_owned();
        let rp_name = optional_text(&rp, "name")?;
        let user = MapView::from_value(m.get_int_key(0x03).ok_or(Status::MissingParameter)?)?;
        let user_id = as_bytes(user.get_text_key("id").ok_or(Status::MissingParameter)?)?.to_vec();
        let user_name = optional_text(&user, "name")?;
        let user_display_name = optional_text(&user, "displayName")?;
        let cred_params = as_array(m.get_int_key(0x04).ok_or(Status::MissingParameter)?)?;

        self.pin_uv_auth(&m, 0x08, 0x09, Some(&rp_id))?;

        if user_id.len() > MAX_USER_ID_LEN {
            return Err(Status::InvalidLength);
        }
        let mut es256 = false;
        for p in cred_params {
            let pm = MapView::from_value(p)?;
            let ty = as_text(pm.get_text_key("type").ok_or(Status::MissingParameter)?)?;
            let alg = as_int(pm.get_text_key("alg").ok_or(Status::MissingParameter)?)?;
            if ty == "public-key" && alg == COSE_ALG_ES256 as i128 {
                es256 = true;
            }
        }
        if !es256 {
            return Err(Status::UnsupportedAlgorithm);
        }
        let exclude = match m.get_int_key(0x05) {
            Some(v) => parse_descriptors(v)?,
            None => Vec::new(),
        };
        if let Some(ext) = m.get_int_key(0x06) {
            MapView::from_value(ext)?; // no extensions supported; must still be a map
        }
        let opts = parse_options(m.get_int_key(0x07))?;
        if m.get_int_key(0x0a).is_some() {
            return Err(Status::InvalidParameter); // enterprise attestation unsupported
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
            user_name.as_deref(),
            want_uv,
        )?;
        let mut flags = FLAG_UP;
        if presence.user_verified {
            flags |= FLAG_UV;
        }

        let key = self
            .backend
            .create_key(&rp_id, &user_id)
            .map_err(backend_err)?;
        let mut cred_id = vec![0u8; CREDENTIAL_ID_LEN];
        OsRng.fill_bytes(&mut cred_id);
        let counter = match self.store.next_sign_count() {
            Ok(c) => c,
            Err(e) => {
                let _ = self.backend.delete_key(&key.handle);
                return Err(store_err(e));
            }
        };
        let public_key =
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key.public_key, false)
                .as_bytes()
                .to_vec();
        let cred = Credential {
            id: cred_id.clone(),
            rp_id: rp_id.clone(),
            rp_name,
            user_id: user_id.clone(),
            user_name,
            user_display_name,
            key_handle: key.handle.clone(),
            public_key,
            discoverable: rk,
            created: counter as u64,
        };
        let cose = authdata::cose_key(&key.public_key);
        let auth_data = authdata::build(
            &rp_id,
            flags,
            counter,
            Some(&AttestedCredential {
                aaguid: &self.config.aaguid,
                credential_id: &cred_id,
                cose_key: &cose,
            }),
            None,
        );
        let (fmt, att_stmt) = match self.config.attestation {
            AttestationFormat::None => ("none", Value::Map(vec![])),
            AttestationFormat::PackedSelf => {
                let mut msg = auth_data.clone();
                msg.extend_from_slice(&client_data_hash);
                let sig = match self.sign_checked(&cred, &msg) {
                    Ok(sig) => sig,
                    Err(e) => {
                        let _ = self.backend.delete_key(&key.handle);
                        return Err(e);
                    }
                };
                (
                    "packed",
                    Value::Map(vec![
                        (text("alg"), int(COSE_ALG_ES256)),
                        (text("sig"), Value::Bytes(sig)),
                    ]),
                )
            }
        };
        // Resident credential for the same RP + user replaces the old one.
        let replaced: Vec<Credential> = if rk {
            self.store
                .list_rp(&rp_id)
                .map_err(store_err)?
                .into_iter()
                .filter(|c| c.discoverable && c.user_id == user_id)
                .collect()
        } else {
            Vec::new()
        };
        if let Err(e) = self.store.insert(cred.clone()) {
            let _ = self.backend.delete_key(&key.handle);
            return Err(store_err(e));
        }
        for old in replaced {
            let _ = self.store.remove(&old.id);
            let _ = self.backend.delete_key(&old.key_handle);
        }

        Ok(Value::Map(vec![
            (int(0x01), text(fmt)),
            (int(0x02), Value::Bytes(auth_data)),
            (int(0x03), att_stmt),
        ]))
    }

    fn assertion_entries(
        &mut self,
        rp_id: &str,
        client_data_hash: &[u8],
        flags: u8,
        user_verified: bool,
        cred: &Credential,
    ) -> Result<Vec<(Value, Value)>, Status> {
        let counter = self.store.next_sign_count().map_err(store_err)?;
        let auth_data = authdata::build(rp_id, flags, counter, None, None);
        let mut msg = auth_data.clone();
        msg.extend_from_slice(client_data_hash);
        let sig = self.sign_checked(cred, &msg)?;
        let mut entries = vec![
            (
                int(0x01),
                Value::Map(vec![
                    (text("id"), bytes(&cred.id)),
                    (text("type"), text("public-key")),
                ]),
            ),
            (int(0x02), Value::Bytes(auth_data)),
            (int(0x03), Value::Bytes(sig)),
        ];
        if cred.discoverable {
            let mut user = vec![(text("id"), bytes(&cred.user_id))];
            // Identifying information only after user verification.
            if user_verified {
                if let Some(n) = &cred.user_name {
                    user.push((text("name"), text(n)));
                }
                if let Some(n) = &cred.user_display_name {
                    user.push((text("displayName"), text(n)));
                }
            }
            entries.push((int(0x04), Value::Map(user)));
        }
        Ok(entries)
    }

    fn get_assertion(&mut self, params: &Value) -> Result<Value, Status> {
        let m = MapView::from_value(params)?;
        let rp_id = as_text(m.get_int_key(0x01).ok_or(Status::MissingParameter)?)?.to_owned();
        let client_data_hash =
            as_bytes(m.get_int_key(0x02).ok_or(Status::MissingParameter)?)?.to_vec();
        self.pin_uv_auth(&m, 0x06, 0x07, Some(&rp_id))?;
        let allow = match m.get_int_key(0x03) {
            Some(v) => parse_descriptors(v)?,
            None => Vec::new(),
        };
        if let Some(ext) = m.get_int_key(0x04) {
            MapView::from_value(ext)?;
        }
        let opts = parse_options(m.get_int_key(0x05))?;
        if opts.rk.is_some() {
            return Err(Status::UnsupportedOption);
        }
        let want_up = opts.up.unwrap_or(true);
        let want_uv = opts.uv == Some(true);
        if want_uv && !self.config.builtin_uv {
            return Err(Status::UnsupportedOption);
        }

        let using_allow_list = !allow.is_empty();
        let mut creds = Vec::new();
        if using_allow_list {
            for id in &allow {
                if let Some(c) = self.store.get(id).map_err(store_err)? {
                    if c.rp_id == rp_id && !creds.iter().any(|x: &Credential| x.id == c.id) {
                        creds.push(c);
                    }
                }
            }
        } else {
            creds = self
                .store
                .list_rp(&rp_id)
                .map_err(store_err)?
                .into_iter()
                .filter(|c| c.discoverable)
                .collect();
            creds.sort_by_key(|c| std::cmp::Reverse(c.created));
        }

        let mut flags = 0u8;
        let mut user_verified = false;
        if want_up || want_uv {
            // Presence is collected even when nothing matches, so a site
            // cannot silently probe for credentials.
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
        let mut entries =
            self.assertion_entries(&rp_id, &client_data_hash, flags, user_verified, &first)?;
        if !using_allow_list && !creds.is_empty() {
            entries.push((int(0x05), int(creds.len() as i64 + 1)));
            self.pending = Some(PendingAssertions {
                rp_id,
                client_data_hash,
                flags,
                user_verified,
                remaining: creds,
                started: Instant::now(),
            });
        }
        Ok(Value::Map(entries))
    }

    fn get_next_assertion(&mut self) -> Result<Value, Status> {
        let mut p = self.pending.take().ok_or(Status::NotAllowed)?;
        if p.started.elapsed() > NEXT_ASSERTION_TIMEOUT || p.remaining.is_empty() {
            return Err(Status::NotAllowed);
        }
        let cred = p.remaining.remove(0);
        let entries = self.assertion_entries(
            &p.rp_id,
            &p.client_data_hash,
            p.flags,
            p.user_verified,
            &cred,
        )?;
        if !p.remaining.is_empty() {
            p.started = Instant::now();
            self.pending = Some(p);
        }
        Ok(Value::Map(entries))
    }

    fn reset(&mut self) -> Result<(), Status> {
        self.ask(PresenceKind::Reset, None, None, false)?;
        let removed = self.store.clear().map_err(store_err)?;
        for c in removed {
            let _ = self.backend.delete_key(&c.key_handle);
        }
        Ok(())
    }
}
