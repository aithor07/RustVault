use std::{error::Error, fmt};

#[derive(Debug)]
pub enum VaultError {
    Database(rusqlite::Error),
    Security(crate::security::SecurityError),
    Io(std::io::Error),
    LegacySchema,
    InvalidConfig(&'static str),
    InvalidMasterPassword,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Error de SQLite: {e}"),
            Self::Security(e) => write!(f, "Error criptográfico: {e}"),
            Self::Io(e) => write!(f, "Error de entrada/salida: {e}"),
            Self::LegacySchema => write!(
                f,
                "La base de datos usa el esquema antiguo sin cifrar. Haz una copia de seguridad y usa una base de datos nueva; no se realizará una migración automática."
            ),
            Self::InvalidConfig(msg) => write!(f, "Configuración del almacén inválida: {msg}"),
            Self::InvalidMasterPassword => write!(
                f,
                "Contraseña maestra incorrecta o comprobación de integridad fallida"
            ),
        }
    }
}

impl Error for VaultError {}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}
impl From<crate::security::SecurityError> for VaultError {
    fn from(e: crate::security::SecurityError) -> Self {
        Self::Security(e)
    }
}
impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
