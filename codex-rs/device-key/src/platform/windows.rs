use crate::DeviceKeyAlgorithm;
use crate::DeviceKeyError;
use crate::DeviceKeyInfo;
use crate::DeviceKeyProtectionClass;
use crate::DeviceKeyProvider;
use crate::ProviderCreateRequest;
use crate::ProviderSignature;
use crate::sec1_public_key_to_spki_der;
use p256::ecdsa::Signature;
use sha2::Digest;
use sha2::Sha256;
use std::mem::size_of;
use std::ptr;
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Foundation::NTE_EXISTS;
use windows_sys::Win32::Security::Cryptography::BCRYPT_ECCKEY_BLOB;
use windows_sys::Win32::Security::Cryptography::BCRYPT_ECCPUBLIC_BLOB;
use windows_sys::Win32::Security::Cryptography::BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
use windows_sys::Win32::Security::Cryptography::MS_PLATFORM_CRYPTO_PROVIDER;
use windows_sys::Win32::Security::Cryptography::NCRYPT_ECDSA_P256_ALGORITHM;
use windows_sys::Win32::Security::Cryptography::NCRYPT_HANDLE;
use windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE;
use windows_sys::Win32::Security::Cryptography::NCRYPT_PROV_HANDLE;
use windows_sys::Win32::Security::Cryptography::NCRYPT_SILENT_FLAG;
use windows_sys::Win32::Security::Cryptography::NCryptCreatePersistedKey;
use windows_sys::Win32::Security::Cryptography::NCryptExportKey;
use windows_sys::Win32::Security::Cryptography::NCryptFinalizeKey;
use windows_sys::Win32::Security::Cryptography::NCryptFreeObject;
use windows_sys::Win32::Security::Cryptography::NCryptOpenKey;
use windows_sys::Win32::Security::Cryptography::NCryptOpenStorageProvider;
use windows_sys::Win32::Security::Cryptography::NCryptSignHash;
use windows_sys::core::HRESULT;

#[derive(Debug)]
pub(crate) struct WindowsDeviceKeyProvider;

impl DeviceKeyProvider for WindowsDeviceKeyProvider {
    fn create(&self, request: ProviderCreateRequest<'_>) -> Result<DeviceKeyInfo, DeviceKeyError> {
        if !request
            .protection_policy
            .allows(DeviceKeyProtectionClass::HardwareTpm)
        {
            return Err(DeviceKeyError::DegradedProtectionNotAllowed {
                available: DeviceKeyProtectionClass::HardwareTpm,
            });
        }

        let provider = open_platform_provider()?;
        let name = key_name(request.key_id);
        if let Some(key) = open_key(&provider, &name)? {
            return key_info(request.key_id, &key);
        }

        let key = create_or_open_key(&provider, &name)?;
        key_info(request.key_id, &key)
    }

    fn get_public(&self, key_id: &str) -> Result<DeviceKeyInfo, DeviceKeyError> {
        let provider = open_platform_provider()?;
        let key = open_key(&provider, &key_name(key_id))?.ok_or(DeviceKeyError::KeyNotFound)?;
        key_info(key_id, &key)
    }

    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<ProviderSignature, DeviceKeyError> {
        let provider = open_platform_provider()?;
        let key = open_key(&provider, &key_name(key_id))?.ok_or(DeviceKeyError::KeyNotFound)?;
        let digest = Sha256::digest(payload);
        let signature = sign_hash(&key, &digest)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|err| DeviceKeyError::Crypto(err.to_string()))?;
        Ok(ProviderSignature {
            signature_der: signature.to_der().as_bytes().to_vec(),
            algorithm: DeviceKeyAlgorithm::EcdsaP256Sha256,
        })
    }
}

#[derive(Debug)]
struct ProviderHandle(NCRYPT_PROV_HANDLE);

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0 as NCRYPT_HANDLE);
        }
    }
}

#[derive(Debug)]
struct KeyHandle(NCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0 as NCRYPT_HANDLE);
        }
    }
}

fn open_platform_provider() -> Result<ProviderHandle, DeviceKeyError> {
    let mut provider = 0;
    let status = unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            /*dwflags*/ 0,
        )
    };
    if status != 0 {
        return Err(DeviceKeyError::HardwareBackedKeysUnavailable);
    }
    Ok(ProviderHandle(provider))
}

fn open_key(provider: &ProviderHandle, name: &[u16]) -> Result<Option<KeyHandle>, DeviceKeyError> {
    let mut key = 0;
    let status = unsafe {
        NCryptOpenKey(
            provider.0,
            &mut key,
            name.as_ptr(),
            /*dwlegacykeyspec*/ 0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status == NTE_BAD_KEYSET {
        return Ok(None);
    }
    if status != 0 {
        return Err(DeviceKeyError::Platform(format_hresult(
            "NCryptOpenKey",
            status,
        )));
    }
    Ok(Some(KeyHandle(key)))
}

fn create_or_open_key(
    provider: &ProviderHandle,
    name: &[u16],
) -> Result<KeyHandle, DeviceKeyError> {
    match create_key(provider, name) {
        Ok(key) => Ok(key),
        Err(KeyCreationError::AlreadyExists) => {
            open_key(provider, name)?.ok_or(DeviceKeyError::KeyNotFound)
        }
        Err(KeyCreationError::Failed(err)) => Err(err),
    }
}

enum KeyCreationError {
    AlreadyExists,
    Failed(DeviceKeyError),
}

fn create_key(provider: &ProviderHandle, name: &[u16]) -> Result<KeyHandle, KeyCreationError> {
    let mut key = 0;
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut key,
            NCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            /*dwlegacykeyspec*/ 0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status == NTE_EXISTS {
        return Err(KeyCreationError::AlreadyExists);
    }
    if status != 0 {
        return Err(KeyCreationError::Failed(DeviceKeyError::Platform(
            format_hresult("NCryptCreatePersistedKey", status),
        )));
    }

    let key = KeyHandle(key);
    let status = unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) };
    if status != 0 {
        return Err(KeyCreationError::Failed(DeviceKeyError::Platform(
            format_hresult("NCryptFinalizeKey", status),
        )));
    }
    Ok(key)
}

fn key_info(key_id: &str, key: &KeyHandle) -> Result<DeviceKeyInfo, DeviceKeyError> {
    Ok(DeviceKeyInfo {
        key_id: key_id.to_string(),
        public_key_spki_der: export_public_key_spki_der(key)?,
        algorithm: DeviceKeyAlgorithm::EcdsaP256Sha256,
        protection_class: DeviceKeyProtectionClass::HardwareTpm,
    })
}

fn export_public_key_spki_der(key: &KeyHandle) -> Result<Vec<u8>, DeviceKeyError> {
    let blob = ncrypt_export_key(key, BCRYPT_ECCPUBLIC_BLOB)?;
    let header_len = size_of::<BCRYPT_ECCKEY_BLOB>();
    if blob.len() < header_len {
        return Err(DeviceKeyError::Platform(
            "NCryptExportKey returned a truncated ECC public key header".to_string(),
        ));
    }

    let header = unsafe { ptr::read_unaligned(blob.as_ptr() as *const BCRYPT_ECCKEY_BLOB) };
    if header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
        return Err(DeviceKeyError::Platform(format!(
            "NCryptExportKey returned unsupported ECC public key magic {}",
            header.dwMagic
        )));
    }

    let coordinate_len =
        usize::try_from(header.cbKey).map_err(|err| DeviceKeyError::Platform(err.to_string()))?;
    let expected_len = header_len + coordinate_len * 2;
    if blob.len() != expected_len {
        return Err(DeviceKeyError::Platform(format!(
            "NCryptExportKey returned ECC public key length {}, expected {expected_len}",
            blob.len()
        )));
    }

    let mut sec1 = Vec::with_capacity(1 + coordinate_len * 2);
    sec1.push(0x04);
    sec1.extend_from_slice(&blob[header_len..]);
    sec1_public_key_to_spki_der(&sec1)
}

fn sign_hash(key: &KeyHandle, digest: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    let mut len = 0;
    let status = unsafe {
        NCryptSignHash(
            key.0,
            ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            ptr::null_mut(),
            /*cbsignature*/ 0,
            &mut len,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(DeviceKeyError::Platform(format_hresult(
            "NCryptSignHash",
            status,
        )));
    }

    let mut signature = vec![0; len as usize];
    let status = unsafe {
        NCryptSignHash(
            key.0,
            ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            signature.len() as u32,
            &mut len,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(DeviceKeyError::Platform(format_hresult(
            "NCryptSignHash",
            status,
        )));
    }
    signature.truncate(len as usize);
    Ok(signature)
}

fn ncrypt_export_key(key: &KeyHandle, blob_type: *const u16) -> Result<Vec<u8>, DeviceKeyError> {
    let mut len = 0;
    let status = unsafe {
        NCryptExportKey(
            key.0,
            /*hexportkey*/ 0,
            blob_type,
            ptr::null(),
            ptr::null_mut(),
            /*cboutput*/ 0,
            &mut len,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(DeviceKeyError::Platform(format_hresult(
            "NCryptExportKey",
            status,
        )));
    }

    let mut blob = vec![0; len as usize];
    let status = unsafe {
        NCryptExportKey(
            key.0,
            /*hexportkey*/ 0,
            blob_type,
            ptr::null(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut len,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(DeviceKeyError::Platform(format_hresult(
            "NCryptExportKey",
            status,
        )));
    }
    blob.truncate(len as usize);
    Ok(blob)
}

fn key_name(key_id: &str) -> Vec<u16> {
    format!("CodexDeviceKey.{key_id}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn format_hresult(function: &str, status: HRESULT) -> String {
    format!("{function} failed with HRESULT 0x{:08x}", status as u32)
}
