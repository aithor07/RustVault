use crate::{
    credential::{Credential, CredentialSummary, NewCredential},
    terminal::read_input,
    vault::Vault,
};
use colored::Colorize;

const MENU: &str = r#"
1. Añade una credencial.
2. Encuentra una credencial.
3. Elimina una credencial.
4. Muestra las credenciales almacenadas.
5. Muestra las credenciales ordenadas por servicio.
6. Salir.
7. Mostrar una contraseña (advertencia de seguridad).
"#;

enum OptionMenu {
    AddCredential,
    FindCredential,
    DeleteCredential,
    ListCredentials,
    SortCredentials,
    Exit,
    RevealPassword,
}

impl OptionMenu {
    fn from_number(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::AddCredential),
            2 => Some(Self::FindCredential),
            3 => Some(Self::DeleteCredential),
            4 => Some(Self::ListCredentials),
            5 => Some(Self::SortCredentials),
            6 => Some(Self::Exit),
            7 => Some(Self::RevealPassword),
            _ => None,
        }
    }
}

pub fn menu(vault: &Vault) {
    println!(
        "{}",
        "=== RustVault - Tu Gestor de Confianza ===".cyan().bold()
    );
    loop {
        println!("{MENU}");
        let choice = match read_input("Elige una opción: ") {
            Ok(choice) => choice,
            Err(error) => {
                eprintln!("{} {error}", "Error leyendo entrada:".red());
                break;
            }
        };
        let number = match choice.parse::<u8>() {
            Ok(number) => number,
            Err(_) => {
                println!("{}", "Debes introducir un número válido.".red());
                continue;
            }
        };
        let option = match OptionMenu::from_number(number) {
            Some(option) => option,
            None => {
                println!("{}", "La opción seleccionada no existe.".red());
                continue;
            }
        };
        match option {
            OptionMenu::AddCredential => add_credential(vault),
            OptionMenu::FindCredential => find_credential(vault),
            OptionMenu::DeleteCredential => delete_credential(vault),
            OptionMenu::ListCredentials => list_credentials(vault),
            OptionMenu::SortCredentials => list_sorted_credentials(vault),
            OptionMenu::RevealPassword => reveal_password(vault),
            OptionMenu::Exit => {
                println!("Hasta luego.");
                break;
            }
        }
    }
}

fn ask(prompt: &str) -> Option<String> {
    match read_input(prompt) {
        Ok(input) => Some(input),
        Err(error) => {
            eprintln!("{} {error}", "Error leyendo entrada:".red());
            None
        }
    }
}

fn add_credential(vault: &Vault) {
    let Some(service) = ask("Servicio: ") else {
        return;
    };
    let Some(username) = ask("Usuario o correo: ") else {
        return;
    };
    // No introducir la contraseña mediante read_input: aparecería en pantalla.
    let password = match rpassword::prompt_password("Contraseña (no visible): ") {
        Ok(password) => password,
        Err(error) => {
            eprintln!("{} {error}", "Error leyendo contraseña:".red());
            return;
        }
    };
    if service.is_empty() || username.is_empty() {
        println!("{}", "Servicio y usuario no pueden estar vacíos.".red());
        return;
    }
    let credential = NewCredential::new(service, username, password);
    match vault.add_credential(&credential) {
        Ok(()) => println!("{}", "Credencial añadida con éxito.".green()),
        Err(error) => eprintln!("{} {error}", "Error al añadir la credencial:".red()),
    }
}

fn find_credential(vault: &Vault) {
    let Some(service) = ask("Servicio: ") else {
        return;
    };
    let Some(username) = ask("Usuario o correo: ") else {
        return;
    };
    if service.is_empty() || username.is_empty() {
        println!("{}", "Servicio y usuario no pueden estar vacíos.".red());
        return;
    }
    match vault.find_credential(&service, &username) {
        Ok(Some(credential)) => print_credential(&credential),
        Ok(None) => println!("{}", "No se encontró esa credencial.".yellow()),
        Err(error) => eprintln!("{} {error}", "Error al buscar la credencial:".red()),
    }
}

fn delete_credential(vault: &Vault) {
    let Some(mode) = ask("Eliminar por (1) ID o (2) servicio y usuario: ") else {
        return;
    };
    let result = match mode.as_str() {
        "1" => {
            let Some(id_input) = ask("ID de la credencial: ") else {
                return;
            };
            let id = match id_input.parse::<i64>() {
                Ok(id) if id > 0 => id,
                _ => {
                    println!("{}", "Debes introducir un ID positivo válido.".red());
                    return;
                }
            };
            vault.delete_credential(Some(id), "", "")
        }
        "2" => {
            let Some(service) = ask("Servicio: ") else {
                return;
            };
            let Some(username) = ask("Usuario o correo: ") else {
                return;
            };
            if service.is_empty() || username.is_empty() {
                println!("{}", "Servicio y usuario no pueden estar vacíos.".red());
                return;
            }
            vault.delete_credential(None, &service, &username)
        }
        _ => {
            println!("{}", "Modo de eliminación no válido.".red());
            return;
        }
    };
    match result {
        Ok(true) => println!("{}", "Credencial eliminada con éxito.".green()),
        Ok(false) => println!("{}", "No se encontró esa credencial.".yellow()),
        Err(error) => eprintln!("{} {error}", "Error al eliminar la credencial:".red()),
    }
}

fn list_credentials(vault: &Vault) {
    match vault.list_all_credentials() {
        Ok(credentials) => print_credentials(&credentials),
        Err(error) => eprintln!("{} {error}", "Error al listar credenciales:".red()),
    }
}

fn list_sorted_credentials(vault: &Vault) {
    match vault.list_credentials_sorted() {
        Ok(credentials) => print_credentials(&credentials),
        Err(error) => eprintln!("{} {error}", "Error al ordenar credenciales:".red()),
    }
}

fn print_credentials(credentials: &[CredentialSummary]) {
    if credentials.is_empty() {
        println!("No hay credenciales almacenadas.");
        return;
    }
    println!("Total de credenciales: {}", credentials.len());
    for credential in credentials {
        println!(
            "ID: {} | Servicio: {} | Usuario: {} | Creada: {}",
            credential.id, credential.service, credential.username, credential.created_at
        );
    }
}

fn print_credential(credential: &Credential) {
    println!(
        "ID: {} | Servicio: {} | Usuario: {} | Creada: {}",
        credential.id, credential.service, credential.username, credential.created_at
    );
    println!("Contraseña: [oculta; utiliza la opción 7 para mostrarla]");
}

fn reveal_password(vault: &Vault) {
    let Some(service) = ask("Servicio: ") else {
        return;
    };
    let Some(username) = ask("Usuario o correo: ") else {
        return;
    };
    println!("{}", "Advertencia: la contraseña aparecerá en la terminal y podría quedar en su historial visual.".yellow());
    let Some(confirm) = ask("¿Mostrarla? (escribe SI): ") else {
        return;
    };
    if confirm != "SI" {
        println!("Operación cancelada.");
        return;
    }
    match vault.find_credential(&service, &username) {
        Ok(Some(credential)) => println!("Contraseña: {}", credential.password.as_str()),
        Ok(None) => println!("{}", "No se encontró esa credencial.".yellow()),
        Err(error) => eprintln!("{} {error}", "Error al descifrar:".red()),
    }
}
