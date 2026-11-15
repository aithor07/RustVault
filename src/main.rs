mod cli;
mod credential;
mod database;
mod error;
mod security;
mod terminal;
mod vault;

use colored::Colorize;
use error::{Result, VaultError};
use rusqlite::Connection;
use zeroize::Zeroizing;

fn unlock_vault(conn: &Connection) -> Result<security::EncryptionKey> {
    match database::read_master_config(conn)? {
        Some(config) => {
            let master = Zeroizing::new(rpassword::prompt_password("Contraseña maestra: ")?);
            let key = security::derive_key(
                &master,
                &config.salt,
                config.m_cost,
                config.t_cost,
                config.p_cost,
            )?;
            database::verify_master_key(&config, &key)?;
            Ok(key)
        }
        None => {
            if !database::database_is_empty(conn)? {
                return Err(VaultError::InvalidConfig(
                    "Hay credenciales, pero no existe la configuración de la clave maestra",
                ));
            }
            println!("Primer inicio: define tu contraseña maestra.");
            println!("Si la olvidas, no podrás recuperar las contraseñas cifradas.");
            let master = Zeroizing::new(rpassword::prompt_password("Nueva contraseña maestra: ")?);
            let confirmation = Zeroizing::new(rpassword::prompt_password("Repítela: ")?);
            if master.is_empty() || master.as_str() != confirmation.as_str() {
                return Err(VaultError::InvalidConfig(
                    "La contraseña maestra está vacía o no coincide",
                ));
            }
            let salt = security::generate_salt();
            let key = security::derive_key(
                &master,
                &salt,
                security::KDF_M_COST,
                security::KDF_T_COST,
                security::KDF_P_COST,
            )?;
            database::create_master_config(conn, &key, salt)?;
            Ok(key)
        }
    }
}

fn run() -> Result<()> {
    let conn = database::open_database()?;
    database::init_database(&conn)?;
    let key = unlock_vault(&conn)?;
    let repository = database::SqliteCredentialRepository::new(conn, key);
    let vault = vault::Vault::new(repository);
    println!("{}", "Almacén desbloqueado.".green());
    cli::menu(&vault);
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(error) => {
            eprintln!("{} {error}", "No se pudo iniciar RustVault:".red());
            std::process::exit(1);
        }
    }
}
