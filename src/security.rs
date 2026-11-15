//! Cifrado autenticado de contraseñas. No implementa un formato de archivo público.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use std::fmt;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

// Perfil explícito de Argon2id: 19 MiB, 2 iteraciones, un carril.
pub const KDF_M_COST: u32 = 19_456;
pub const KDF_T_COST: u32 = 2;
pub const KDF_P_COST: u32 = 1;

pub type EncryptionKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug)]
pub enum SecurityError {
    KeyDerivation,
    Encryption,
    Decryption,
    InvalidUtf8,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyDerivation => write!(f, "No se ha podido derivar la clave"),
            Self::Encryption => write!(f, "No se ha podido cifrar la contraseña"),
            Self::Decryption => write!(f, "Clave incorrecta o datos cifrados manipulados"),
            Self::InvalidUtf8 => write!(f, "La contraseña descifrada no es UTF-8"),
        }
    }
}
impl std::error::Error for SecurityError {}

pub struct EncryptedPassword {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<EncryptionKey, SecurityError> {
    // Limitar los parámetros procedentes de SQLite evita asignaciones excesivas
    // si la configuración está dañada o manipulada.
    if !(8_192..=1_048_576).contains(&m_cost)
        || !(1..=10).contains(&t_cost)
        || !(1..=8).contains(&p_cost)
    {
        return Err(SecurityError::KeyDerivation);
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| SecurityError::KeyDerivation)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(master_password.as_bytes(), salt, &mut *key)
        .map_err(|_| SecurityError::KeyDerivation)?;
    Ok(key)
}

// Asociamos servicio y usuario al cifrado para impedir intercambiar
// ciphertexts entre registros sin que la autenticación lo detecte.
fn associated_data(service: &str, username: &str) -> Vec<u8> {
    let mut data = b"RustVault:credential:v1".to_vec();
    data.extend_from_slice(&(service.len() as u64).to_be_bytes());
    data.extend_from_slice(service.as_bytes());
    data.extend_from_slice(&(username.len() as u64).to_be_bytes());
    data.extend_from_slice(username.as_bytes());
    data
}

pub fn encrypt_password(
    password: &str,
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
) -> Result<EncryptedPassword, SecurityError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SecurityError::Encryption)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = associated_data(service, username);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: password.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| SecurityError::Encryption)?;
    Ok(EncryptedPassword { ciphertext, nonce })
}

pub fn decrypt_password(
    encrypted: &EncryptedPassword,
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
) -> Result<Zeroizing<String>, SecurityError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SecurityError::Decryption)?;
    let aad = associated_data(service, username);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&encrypted.nonce),
            Payload {
                msg: encrypted.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| SecurityError::Decryption)?;
    // String toma posesión del buffer. Zeroizing lo limpiará al liberarse.
    let password = String::from_utf8(plaintext).map_err(|_| SecurityError::InvalidUtf8)?;
    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EncryptionKey {
        derive_key(
            "test-master",
            &generate_salt(),
            KDF_M_COST,
            KDF_T_COST,
            KDF_P_COST,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let encrypted = encrypt_password("fake_password", &key, "Github", "test").unwrap();
        assert_eq!(
            &*decrypt_password(&encrypted, &key, "Github", "test").unwrap(),
            "fake_password"
        );
    }

    #[test]
    fn wrong_key_and_modified_metadata_fail() {
        let key = test_key();
        let other_key = test_key();
        let encrypted = encrypt_password("fake_password", &key, "Github", "test").unwrap();
        assert!(decrypt_password(&encrypted, &other_key, "Github", "test").is_err());
        assert!(decrypt_password(&encrypted, &key, "Other", "test").is_err());
    }

    #[test]
    fn changed_ciphertext_fails() {
        let key = test_key();
        let mut encrypted = encrypt_password("fake_password", &key, "Github", "test").unwrap();
        encrypted.ciphertext[0] ^= 1;
        assert!(decrypt_password(&encrypted, &key, "Github", "test").is_err());
    }

    #[test]
    fn distinct_nonces() {
        let key = test_key();
        let a = encrypt_password("fake_password", &key, "Github", "test").unwrap();
        let b = encrypt_password("fake_password", &key, "Github", "test").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }
}
