use zeroize::Zeroizing;

/// Datos de una credencial almacenada, con contraseña descifrada solo en memoria.
pub struct Credential {
    pub id: i64,
    pub service: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub created_at: String,
}

/// Datos públicos de una credencial: no es necesario descifrarla para listarla.
pub struct CredentialSummary {
    pub id: i64,
    pub service: String,
    pub username: String,
    pub created_at: String,
}

/// Datos nuevos; Zeroizing borra el buffer de contraseña al liberarlo.
pub struct NewCredential {
    pub service: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl NewCredential {
    pub fn new(service: String, username: String, password: String) -> Self {
        Self {
            service,
            username,
            password: Zeroizing::new(password),
        }
    }
}
