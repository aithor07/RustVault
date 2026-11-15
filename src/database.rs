use crate::{
    credential::{Credential, CredentialSummary, NewCredential},
    error::{Result, VaultError},
    security::{self, EncryptedPassword, EncryptionKey, NONCE_LEN, SALT_LEN},
};
use rusqlite::{Connection, OptionalExtension, params};

const MASTER_CHECK: &str = "RustVault:master-check:v1";
const CHECK_SERVICE: &str = "RustVault:internal";
const CHECK_USERNAME: &str = "master-check";

pub fn open_database() -> Result<Connection> {
    Ok(Connection::open("./rustvault.db")?)
}

pub fn init_database(conn: &Connection) -> Result<()> {
    // No convertir automáticamente una base que guarda contraseñas en claro.
    let mut stmt = conn.prepare("PRAGMA table_info(credentials)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut names = Vec::new();
    for column in columns {
        names.push(column?);
    }
    if !names.is_empty() && !names.iter().any(|name| name == "nonce") {
        return Err(VaultError::LegacySchema);
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(service, username)
        );
        CREATE TABLE IF NOT EXISTS vault_config (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            salt BLOB NOT NULL,
            kdf_m_cost INTEGER NOT NULL,
            kdf_t_cost INTEGER NOT NULL,
            kdf_p_cost INTEGER NOT NULL,
            check_nonce BLOB NOT NULL,
            check_ciphertext BLOB NOT NULL
        );",
    )?;
    Ok(())
}

pub struct MasterConfig {
    pub salt: [u8; SALT_LEN],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub check_nonce: [u8; NONCE_LEN],
    pub check_ciphertext: Vec<u8>,
}

fn fixed_bytes<const N: usize>(source: Vec<u8>, name: &'static str) -> Result<[u8; N]> {
    source
        .try_into()
        .map_err(|_| VaultError::InvalidConfig(name))
}

pub fn read_master_config(conn: &Connection) -> Result<Option<MasterConfig>> {
    let result = conn
        .query_row(
            "SELECT salt, kdf_m_cost, kdf_t_cost, kdf_p_cost, check_nonce, check_ciphertext
         FROM vault_config WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    match result {
        None => Ok(None),
        Some((salt, m_cost, t_cost, p_cost, nonce, ciphertext)) => Ok(Some(MasterConfig {
            salt: fixed_bytes(salt, "salt con longitud incorrecta")?,
            m_cost,
            t_cost,
            p_cost,
            check_nonce: fixed_bytes(nonce, "nonce de verificación inválido")?,
            check_ciphertext: ciphertext,
        })),
    }
}

pub fn create_master_config(
    conn: &Connection,
    key: &EncryptionKey,
    salt: [u8; SALT_LEN],
) -> Result<()> {
    let encrypted = security::encrypt_password(MASTER_CHECK, key, CHECK_SERVICE, CHECK_USERNAME)?;
    match conn.execute(
        "INSERT INTO vault_config
        (id, salt, kdf_m_cost, kdf_t_cost, kdf_p_cost, check_nonce, check_ciphertext)
        VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            salt.as_slice(),
            security::KDF_M_COST,
            security::KDF_T_COST,
            security::KDF_P_COST,
            encrypted.nonce.as_slice(),
            encrypted.ciphertext
        ],
    ) {
        Ok(_) => Ok(()),
        Err(error) => Err(VaultError::Database(error)),
    }
}

pub fn verify_master_key(config: &MasterConfig, key: &EncryptionKey) -> Result<()> {
    let encrypted = EncryptedPassword {
        nonce: config.check_nonce,
        ciphertext: config.check_ciphertext.clone(),
    };
    match security::decrypt_password(&encrypted, key, CHECK_SERVICE, CHECK_USERNAME) {
        Ok(message) if message.as_str() == MASTER_CHECK => Ok(()),
        _ => Err(VaultError::InvalidMasterPassword),
    }
}

pub fn database_is_empty(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;
    Ok(count == 0)
}

pub struct SqliteCredentialRepository {
    conn: Connection,
    key: EncryptionKey,
}

struct EncryptedRow {
    id: i64,
    service: String,
    username: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    created_at: String,
}

impl SqliteCredentialRepository {
    pub fn new(conn: Connection, key: EncryptionKey) -> Self {
        Self { conn, key }
    }

    pub fn add(&self, credential: &NewCredential) -> Result<()> {
        let encrypted = security::encrypt_password(
            &credential.password,
            &self.key,
            &credential.service,
            &credential.username,
        )?;
        match self.conn.execute(
            "INSERT INTO credentials (service, username, password, nonce) VALUES (?1, ?2, ?3, ?4)",
            params![
                credential.service,
                credential.username,
                encrypted.ciphertext,
                encrypted.nonce.as_slice(),
            ],
        ) {
            Ok(_) => Ok(()),
            Err(error) => Err(VaultError::Database(error)),
        }
    }

    fn decrypt_row(&self, row: EncryptedRow) -> Result<Credential> {
        let nonce = fixed_bytes(row.nonce, "nonce de credencial inválido")?;
        let encrypted = EncryptedPassword {
            ciphertext: row.ciphertext,
            nonce,
        };
        let password =
            security::decrypt_password(&encrypted, &self.key, &row.service, &row.username)?;
        Ok(Credential {
            id: row.id,
            service: row.service,
            username: row.username,
            password,
            created_at: row.created_at,
        })
    }

    pub fn find(&self, service: &str, username: &str) -> Result<Option<Credential>> {
        let query = "SELECT id, service, username, password, nonce, created_at
                     FROM credentials WHERE service = ?1 AND username = ?2";
        let found = self
            .conn
            .query_row(query, params![service, username], |row| {
                Ok(EncryptedRow {
                    id: row.get(0)?,
                    service: row.get(1)?,
                    username: row.get(2)?,
                    ciphertext: row.get(3)?,
                    nonce: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .optional()?;
        match found {
            Some(row) => Ok(Some(self.decrypt_row(row)?)),
            None => Ok(None),
        }
    }

    fn summaries(&self, query: &str) -> Result<Vec<CredentialSummary>> {
        let mut stmt = self.conn.prepare(query)?;
        let rows = stmt.query_map([], |row| {
            Ok(CredentialSummary {
                id: row.get(0)?,
                service: row.get(1)?,
                username: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        let mut credentials = Vec::new();
        for row in rows {
            match row {
                Ok(credential) => credentials.push(credential),
                Err(error) => return Err(VaultError::Database(error)),
            }
        }
        Ok(credentials)
    }

    pub fn list_all(&self) -> Result<Vec<CredentialSummary>> {
        self.summaries("SELECT id, service, username, created_at FROM credentials")
    }

    pub fn list_sorted(&self) -> Result<Vec<CredentialSummary>> {
        self.summaries(
            "SELECT id, service, username, created_at FROM credentials
                        ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC",
        )
    }

    pub fn delete(&self, id: Option<i64>, service: &str, username: &str) -> Result<bool> {
        let result = match id {
            Some(id) => self
                .conn
                .execute("DELETE FROM credentials WHERE id = ?1", params![id]),
            None => self.conn.execute(
                "DELETE FROM credentials WHERE service = ?1 AND username = ?2",
                params![service, username],
            ),
        };
        match result {
            Ok(rows) => Ok(rows > 0),
            Err(error) => Err(VaultError::Database(error)),
        }
    }

    pub fn count(&self) -> Result<i64> {
        match self
            .conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
        {
            Ok(count) => Ok(count),
            Err(error) => Err(VaultError::Database(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{KDF_M_COST, KDF_P_COST, KDF_T_COST, derive_key, generate_salt};

    fn setup() -> SqliteCredentialRepository {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        let salt = generate_salt();
        let key = derive_key("test-master", &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST).unwrap();
        create_master_config(&conn, &key, salt).unwrap();
        let config = read_master_config(&conn).unwrap().unwrap();
        verify_master_key(&config, &key).unwrap();
        SqliteCredentialRepository::new(conn, key)
    }

    #[test]
    fn roundtrip_and_counts() {
        let repo = setup();
        repo.add(&NewCredential::new(
            "GitHub".into(),
            "test".into(),
            "fake123".into(),
        ))
        .unwrap();
        assert_eq!(repo.count().unwrap(), 1);
        assert_eq!(repo.list_all().unwrap().len(), 1);
        let cred = repo.find("GitHub", "test").unwrap().unwrap();
        assert_eq!(cred.password.as_str(), "fake123");
        assert!(repo.delete(None, "GitHub", "test").unwrap());
        assert!(!repo.delete(None, "GitHub", "test").unwrap());
        assert_eq!(repo.count().unwrap(), 0);
    }

    #[test]
    fn db_never_stores_plain_password() {
        let repo = setup();
        repo.add(&NewCredential::new(
            "GitHub".into(),
            "test".into(),
            "fake123".into(),
        ))
        .unwrap();
        let blob: Vec<u8> = repo
            .conn
            .query_row("SELECT password FROM credentials", [], |row| row.get(0))
            .unwrap();
        assert_ne!(blob, b"fake123");
    }

    #[test]
    fn wrong_master_fails() {
        let repo = setup();
        let config = read_master_config(&repo.conn).unwrap().unwrap();
        let bad_key = derive_key(
            "wrong-master",
            &config.salt,
            config.m_cost,
            config.t_cost,
            config.p_cost,
        )
        .unwrap();
        assert!(verify_master_key(&config, &bad_key).is_err());
    }

    #[test]
    fn rejects_old_plaintext_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE credentials (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password TEXT)").unwrap();
        assert!(matches!(
            init_database(&conn),
            Err(VaultError::LegacySchema)
        ));
    }
}
