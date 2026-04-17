use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::pkcs8::EncodePublicKey;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use thiserror::Error;

mod platform;

const KEY_ID_DOMAIN: &[u8] = b"codex-device-key/v1";
const SIGNING_DOMAIN: &str = "codex-device-key-sign-payload/v1";
const REMOTE_CONTROL_CONTROLLER_WEBSOCKET_SCOPE: &str = "remote_control_controller_websocket";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyAlgorithm {
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyProtectionClass {
    HardwareSecureEnclave,
    HardwareTpm,
    OsProtectedNonextractable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKeyProtectionPolicy {
    HardwareOnly,
    AllowOsProtectedNonextractable,
}

impl DeviceKeyProtectionPolicy {
    fn allows(self, protection_class: DeviceKeyProtectionClass) -> bool {
        match self {
            Self::HardwareOnly => !protection_class.is_degraded(),
            Self::AllowOsProtectedNonextractable => matches!(
                protection_class,
                DeviceKeyProtectionClass::HardwareSecureEnclave
                    | DeviceKeyProtectionClass::HardwareTpm
                    | DeviceKeyProtectionClass::OsProtectedNonextractable
            ),
        }
    }
}

impl DeviceKeyProtectionClass {
    pub fn is_degraded(self) -> bool {
        match self {
            Self::HardwareSecureEnclave | Self::HardwareTpm => false,
            Self::OsProtectedNonextractable => true,
        }
    }
}

impl fmt::Display for DeviceKeyProtectionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardwareSecureEnclave => f.write_str("hardware_secure_enclave"),
            Self::HardwareTpm => f.write_str("hardware_tpm"),
            Self::OsProtectedNonextractable => f.write_str("os_protected_nonextractable"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyCreateRequest {
    pub account_user_id: String,
    pub client_id: String,
    pub protection_policy: DeviceKeyProtectionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyGetPublicRequest {
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeySignRequest {
    pub key_id: String,
    pub payload: DeviceKeySignPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyInfo {
    pub key_id: String,
    pub public_key_spki_der: Vec<u8>,
    pub algorithm: DeviceKeyAlgorithm,
    pub protection_class: DeviceKeyProtectionClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeySignature {
    pub signature_der: Vec<u8>,
    /// Exact payload bytes covered by `signature_der`.
    pub signed_payload: Vec<u8>,
    pub algorithm: DeviceKeyAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSignature {
    signature_der: Vec<u8>,
    algorithm: DeviceKeyAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DeviceKeySignPayload {
    RemoteControlClientConnection(RemoteControlClientConnectionSignPayload),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteControlClientConnectionAudience {
    RemoteControlClientWebsocket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteControlClientConnectionSignPayload {
    pub nonce: String,
    pub audience: RemoteControlClientConnectionAudience,
    pub session_id: String,
    pub target_origin: String,
    pub target_path: String,
    pub account_user_id: String,
    pub client_id: String,
    pub token_sha256_base64url: String,
    pub token_expires_at: i64,
    pub scopes: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DeviceKeyError {
    #[error(
        "hardware-backed device keys are not available; set protectionPolicy to allow_os_protected_nonextractable to allow key protection class {available}"
    )]
    DegradedProtectionNotAllowed { available: DeviceKeyProtectionClass },
    #[error("hardware-backed device keys are not available on this platform")]
    HardwareBackedKeysUnavailable,
    #[error("device key not found")]
    KeyNotFound,
    #[error("payload does not match device key binding")]
    PayloadBindingMismatch,
    #[error("invalid device key payload: {0}")]
    InvalidPayload(&'static str),
    #[error("device key platform error: {0}")]
    Platform(String),
    #[error("device key cryptography error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone)]
pub struct DeviceKeyStore {
    provider: Arc<dyn DeviceKeyProvider>,
}

impl Default for DeviceKeyStore {
    fn default() -> Self {
        Self {
            provider: platform::default_provider(),
        }
    }
}

impl DeviceKeyStore {
    pub fn create(&self, request: DeviceKeyCreateRequest) -> Result<DeviceKeyInfo, DeviceKeyError> {
        let binding = KeyBinding {
            account_user_id: &request.account_user_id,
            client_id: &request.client_id,
        };
        validate_binding(&binding)?;

        let key_id = stable_key_id(&binding);
        self.provider.create(ProviderCreateRequest {
            key_id: &key_id,
            protection_policy: request.protection_policy,
        })
    }

    pub fn get_public(
        &self,
        request: DeviceKeyGetPublicRequest,
    ) -> Result<DeviceKeyInfo, DeviceKeyError> {
        validate_key_id(&request.key_id)?;
        self.provider.get_public(&request.key_id)
    }

    pub fn sign(
        &self,
        request: DeviceKeySignRequest,
    ) -> Result<DeviceKeySignature, DeviceKeyError> {
        validate_key_id(&request.key_id)?;
        validate_payload(&request.key_id, &request.payload)?;
        let signed_payload = device_key_signing_payload_bytes(&request.payload)?;
        let signature = self.provider.sign(&request.key_id, &signed_payload)?;
        Ok(DeviceKeySignature {
            signature_der: signature.signature_der,
            signed_payload,
            algorithm: signature.algorithm,
        })
    }

    #[cfg(test)]
    fn with_provider(provider: Arc<dyn DeviceKeyProvider>) -> Self {
        Self { provider }
    }
}

#[derive(Debug)]
struct ProviderCreateRequest<'a> {
    key_id: &'a str,
    protection_policy: DeviceKeyProtectionPolicy,
}

/// Owns platform-specific non-exportable key operations for device signing.
///
/// Implementations must never expose a generic arbitrary-byte signing API outside this crate. The
/// crate validates and serializes accepted structured payloads before calling `sign`.
trait DeviceKeyProvider: Debug + Send + Sync {
    fn create(&self, request: ProviderCreateRequest<'_>) -> Result<DeviceKeyInfo, DeviceKeyError>;
    fn get_public(&self, key_id: &str) -> Result<DeviceKeyInfo, DeviceKeyError>;
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<ProviderSignature, DeviceKeyError>;
}

#[derive(Debug)]
struct KeyBinding<'a> {
    account_user_id: &'a str,
    client_id: &'a str,
}

fn stable_key_id(binding: &KeyBinding<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    update_key_id_component(&mut hasher, binding.account_user_id);
    update_key_id_component(&mut hasher, binding.client_id);
    let digest = hasher.finalize();
    format!("dk_{}", URL_SAFE_NO_PAD.encode(digest))
}

fn update_key_id_component(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn validate_binding(binding: &KeyBinding<'_>) -> Result<(), DeviceKeyError> {
    if binding.account_user_id.is_empty() {
        return Err(DeviceKeyError::InvalidPayload(
            "accountUserId must not be empty",
        ));
    }
    if binding.client_id.is_empty() {
        return Err(DeviceKeyError::InvalidPayload("clientId must not be empty"));
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), DeviceKeyError> {
    if key_id.is_empty() {
        return Err(DeviceKeyError::InvalidPayload("keyId must not be empty"));
    }
    Ok(())
}

fn validate_payload(key_id: &str, payload: &DeviceKeySignPayload) -> Result<(), DeviceKeyError> {
    match payload {
        DeviceKeySignPayload::RemoteControlClientConnection(payload) => {
            validate_remote_control_client_connection_payload(key_id, payload)
        }
    }
}

fn validate_remote_control_client_connection_payload(
    key_id: &str,
    payload: &RemoteControlClientConnectionSignPayload,
) -> Result<(), DeviceKeyError> {
    if payload.nonce.is_empty() {
        return Err(DeviceKeyError::InvalidPayload("nonce must not be empty"));
    }
    if payload.session_id.is_empty() {
        return Err(DeviceKeyError::InvalidPayload(
            "sessionId must not be empty",
        ));
    }
    if payload.target_origin.is_empty() {
        return Err(DeviceKeyError::InvalidPayload(
            "targetOrigin must not be empty",
        ));
    }
    if payload.target_path.is_empty() {
        return Err(DeviceKeyError::InvalidPayload(
            "targetPath must not be empty",
        ));
    }
    let binding = KeyBinding {
        account_user_id: &payload.account_user_id,
        client_id: &payload.client_id,
    };
    validate_binding(&binding)?;
    if !is_base64url_sha256(&payload.token_sha256_base64url) {
        return Err(DeviceKeyError::InvalidPayload(
            "tokenSha256Base64url must be a SHA-256 digest encoded as unpadded base64url",
        ));
    }
    if payload.scopes != [REMOTE_CONTROL_CONTROLLER_WEBSOCKET_SCOPE] {
        return Err(DeviceKeyError::InvalidPayload(
            "scopes must contain exactly remote_control_controller_websocket",
        ));
    }
    if stable_key_id(&binding) != key_id {
        return Err(DeviceKeyError::PayloadBindingMismatch);
    }
    if payload.token_expires_at <= current_unix_seconds()? {
        return Err(DeviceKeyError::InvalidPayload(
            "remote-control token is expired",
        ));
    }
    Ok(())
}

fn is_base64url_sha256(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|digest| digest.len() == 32)
}

fn current_unix_seconds() -> Result<i64, DeviceKeyError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DeviceKeyError::InvalidPayload("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_secs())
        .map_err(|_| DeviceKeyError::InvalidPayload("current time does not fit in i64"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedPayload<'a> {
    domain: &'static str,
    payload: &'a DeviceKeySignPayload,
}

/// Returns the exact bytes that device-key providers sign and verifiers must check.
///
/// The representation is UTF-8 JSON with an explicit domain separator and the accepted structured
/// payload. Test vectors in this crate intentionally lock the field names and ordering so non-Rust
/// verifiers can reproduce the same bytes.
pub fn device_key_signing_payload_bytes(
    payload: &DeviceKeySignPayload,
) -> Result<Vec<u8>, DeviceKeyError> {
    serde_json::to_vec(&SignedPayload {
        domain: SIGNING_DOMAIN,
        payload,
    })
    .map_err(|err| DeviceKeyError::Crypto(err.to_string()))
}

#[allow(dead_code)]
fn sec1_public_key_to_spki_der(sec1_public_key: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    let public_key = p256::PublicKey::from_sec1_bytes(sec1_public_key)
        .map_err(|err| DeviceKeyError::Crypto(err.to_string()))?;
    public_key
        .to_public_key_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|err| DeviceKeyError::Crypto(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::Signature;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::signature::Verifier;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::DecodePublicKey;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const TEST_TOKEN_SHA256_BASE64URL: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    #[derive(Debug)]
    struct MemoryProvider {
        class: DeviceKeyProtectionClass,
        keys: Mutex<HashMap<String, SigningKey>>,
    }

    impl MemoryProvider {
        fn new(class: DeviceKeyProtectionClass) -> Self {
            Self {
                class,
                keys: Mutex::new(HashMap::new()),
            }
        }
    }

    impl DeviceKeyProvider for MemoryProvider {
        fn create(
            &self,
            request: ProviderCreateRequest<'_>,
        ) -> Result<DeviceKeyInfo, DeviceKeyError> {
            if !request.protection_policy.allows(self.class) {
                return Err(DeviceKeyError::DegradedProtectionNotAllowed {
                    available: self.class,
                });
            }
            let mut keys = self
                .keys
                .lock()
                .map_err(|err| DeviceKeyError::Platform(err.to_string()))?;
            let signing_key = keys
                .entry(request.key_id.to_string())
                .or_insert_with(|| SigningKey::random(&mut OsRng));
            memory_key_info(request.key_id, signing_key, self.class)
        }

        fn get_public(&self, key_id: &str) -> Result<DeviceKeyInfo, DeviceKeyError> {
            let keys = self
                .keys
                .lock()
                .map_err(|err| DeviceKeyError::Platform(err.to_string()))?;
            let signing_key = keys.get(key_id).ok_or(DeviceKeyError::KeyNotFound)?;
            memory_key_info(key_id, signing_key, self.class)
        }

        fn sign(&self, key_id: &str, payload: &[u8]) -> Result<ProviderSignature, DeviceKeyError> {
            let keys = self
                .keys
                .lock()
                .map_err(|err| DeviceKeyError::Platform(err.to_string()))?;
            let signing_key = keys.get(key_id).ok_or(DeviceKeyError::KeyNotFound)?;
            let signature: Signature = signing_key.sign(payload);
            Ok(ProviderSignature {
                signature_der: signature.to_der().as_bytes().to_vec(),
                algorithm: DeviceKeyAlgorithm::EcdsaP256Sha256,
            })
        }
    }

    fn memory_key_info(
        key_id: &str,
        signing_key: &SigningKey,
        class: DeviceKeyProtectionClass,
    ) -> Result<DeviceKeyInfo, DeviceKeyError> {
        let public_key_spki_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|err| DeviceKeyError::Crypto(err.to_string()))?
            .as_bytes()
            .to_vec();
        Ok(DeviceKeyInfo {
            key_id: key_id.to_string(),
            public_key_spki_der,
            algorithm: DeviceKeyAlgorithm::EcdsaP256Sha256,
            protection_class: class,
        })
    }

    fn store(class: DeviceKeyProtectionClass) -> DeviceKeyStore {
        DeviceKeyStore::with_provider(Arc::new(MemoryProvider::new(class)))
    }

    fn create_request(protection_policy: DeviceKeyProtectionPolicy) -> DeviceKeyCreateRequest {
        DeviceKeyCreateRequest {
            account_user_id: "account-user-1".to_string(),
            client_id: "cli_123".to_string(),
            protection_policy,
        }
    }

    fn remote_control_client_connection_payload() -> DeviceKeySignPayload {
        DeviceKeySignPayload::RemoteControlClientConnection(
            RemoteControlClientConnectionSignPayload {
                nonce: "nonce-1".to_string(),
                audience: RemoteControlClientConnectionAudience::RemoteControlClientWebsocket,
                session_id: "wssess_123".to_string(),
                target_origin: "https://chatgpt.com".to_string(),
                target_path: "/api/codex/remote/control/client".to_string(),
                account_user_id: "account-user-1".to_string(),
                client_id: "cli_123".to_string(),
                token_sha256_base64url: TEST_TOKEN_SHA256_BASE64URL.to_string(),
                token_expires_at: current_unix_seconds().expect("time should be valid") + 60,
                scopes: vec![REMOTE_CONTROL_CONTROLLER_WEBSOCKET_SCOPE.to_string()],
            },
        )
    }

    #[test]
    fn create_requires_explicit_degraded_protection() {
        let err = store(DeviceKeyProtectionClass::OsProtectedNonextractable)
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect_err("OS-protected fallback should require opt-in");

        assert!(
            matches!(
                err,
                DeviceKeyError::DegradedProtectionNotAllowed {
                    available: DeviceKeyProtectionClass::OsProtectedNonextractable,
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn create_allows_os_protected_nonextractable_policy() {
        let info = store(DeviceKeyProtectionClass::OsProtectedNonextractable)
            .create(create_request(
                DeviceKeyProtectionPolicy::AllowOsProtectedNonextractable,
            ))
            .expect("OS-protected fallback should be allowed by policy");

        assert_eq!(
            info.protection_class,
            DeviceKeyProtectionClass::OsProtectedNonextractable
        );
    }

    #[test]
    fn create_reuses_stable_key_for_binding() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let first = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let second = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("existing key should load");

        assert_eq!(second, first);
    }

    #[test]
    fn stable_key_id_encodes_binding_components_unambiguously() {
        let first = stable_key_id(&KeyBinding {
            account_user_id: "account-user\0cli",
            client_id: "123",
        });
        let second = stable_key_id(&KeyBinding {
            account_user_id: "account-user",
            client_id: concat!("cli\0", "123"),
        });

        assert_ne!(first, second);
    }

    #[test]
    fn create_rejects_empty_account_user_id() {
        let err = store(DeviceKeyProtectionClass::HardwareTpm)
            .create(DeviceKeyCreateRequest {
                account_user_id: String::new(),
                client_id: "cli_123".to_string(),
                protection_policy: DeviceKeyProtectionPolicy::HardwareOnly,
            })
            .expect_err("empty account user id should fail before provider access");

        assert!(
            matches!(
                err,
                DeviceKeyError::InvalidPayload("accountUserId must not be empty")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn sign_uses_structured_payload() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let payload = remote_control_client_connection_payload();
        let signed_payload =
            device_key_signing_payload_bytes(&payload).expect("payload should serialize");
        let signature = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect("sign should succeed");
        assert_eq!(signature.signed_payload, signed_payload);

        let verifying_key = VerifyingKey::from_public_key_der(&info.public_key_spki_der)
            .expect("public key should decode");
        let signature =
            Signature::from_der(&signature.signature_der).expect("signature should decode");
        verifying_key
            .verify(&signed_payload, &signature)
            .expect("signature should verify against structured payload");
    }

    #[test]
    fn signing_payload_bytes_are_stable() {
        let payload = DeviceKeySignPayload::RemoteControlClientConnection(
            RemoteControlClientConnectionSignPayload {
                nonce: "nonce-1".to_string(),
                audience: RemoteControlClientConnectionAudience::RemoteControlClientWebsocket,
                session_id: "wssess_123".to_string(),
                target_origin: "https://chatgpt.com".to_string(),
                target_path: "/api/codex/remote/control/client".to_string(),
                account_user_id: "account-user-1".to_string(),
                client_id: "cli_123".to_string(),
                token_sha256_base64url: TEST_TOKEN_SHA256_BASE64URL.to_string(),
                token_expires_at: 1_700_000_000,
                scopes: vec![REMOTE_CONTROL_CONTROLLER_WEBSOCKET_SCOPE.to_string()],
            },
        );

        let bytes = device_key_signing_payload_bytes(&payload).expect("payload should serialize");

        assert_eq!(
            String::from_utf8(bytes).expect("payload should be utf-8"),
            concat!(
                "{\"domain\":\"codex-device-key-sign-payload/v1\",",
                "\"payload\":{\"type\":\"remoteControlClientConnection\",",
                "\"nonce\":\"nonce-1\",",
                "\"audience\":\"remote_control_client_websocket\",",
                "\"sessionId\":\"wssess_123\",",
                "\"targetOrigin\":\"https://chatgpt.com\",",
                "\"targetPath\":\"/api/codex/remote/control/client\",",
                "\"accountUserId\":\"account-user-1\",",
                "\"clientId\":\"cli_123\",",
                "\"tokenSha256Base64url\":\"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\",",
                "\"tokenExpiresAt\":1700000000,",
                "\"scopes\":[\"remote_control_controller_websocket\"]}}"
            )
        );
    }

    #[test]
    fn sign_rejects_malformed_token_hash() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let mut payload = remote_control_client_connection_payload();
        match &mut payload {
            DeviceKeySignPayload::RemoteControlClientConnection(connection_payload) => {
                connection_payload.token_sha256_base64url = "not-a-sha256".to_string();
            }
        }

        let err = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect_err("malformed token hash should fail");

        assert!(
            matches!(
                err,
                DeviceKeyError::InvalidPayload(
                    "tokenSha256Base64url must be a SHA-256 digest encoded as unpadded base64url"
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn sign_rejects_unexpected_scopes() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let mut payload = remote_control_client_connection_payload();
        match &mut payload {
            DeviceKeySignPayload::RemoteControlClientConnection(connection_payload) => {
                connection_payload.scopes = vec!["other_scope".to_string()];
            }
        }

        let err = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect_err("unexpected scope should fail");

        assert!(
            matches!(
                err,
                DeviceKeyError::InvalidPayload(
                    "scopes must contain exactly remote_control_controller_websocket"
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn sign_rejects_empty_target_binding() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let mut payload = remote_control_client_connection_payload();
        match &mut payload {
            DeviceKeySignPayload::RemoteControlClientConnection(connection_payload) => {
                connection_payload.target_origin.clear();
            }
        }

        let err = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect_err("empty target origin should fail");

        assert!(
            matches!(
                err,
                DeviceKeyError::InvalidPayload("targetOrigin must not be empty")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn sign_rejects_empty_session_binding() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let mut payload = remote_control_client_connection_payload();
        match &mut payload {
            DeviceKeySignPayload::RemoteControlClientConnection(connection_payload) => {
                connection_payload.session_id.clear();
            }
        }

        let err = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect_err("empty session id should fail");

        assert!(
            matches!(
                err,
                DeviceKeyError::InvalidPayload("sessionId must not be empty")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn sign_rejects_mismatched_binding() {
        let store = store(DeviceKeyProtectionClass::HardwareTpm);
        let info = store
            .create(create_request(DeviceKeyProtectionPolicy::HardwareOnly))
            .expect("create should succeed");
        let mut payload = remote_control_client_connection_payload();
        match &mut payload {
            DeviceKeySignPayload::RemoteControlClientConnection(connection_payload) => {
                connection_payload.account_user_id = "other-account-user".to_string();
            }
        }

        let err = store
            .sign(DeviceKeySignRequest {
                key_id: info.key_id,
                payload,
            })
            .expect_err("mismatched account should fail");

        assert!(
            matches!(err, DeviceKeyError::PayloadBindingMismatch),
            "unexpected error: {err:?}"
        );
    }
}
