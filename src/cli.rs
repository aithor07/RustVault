use crate::{helpers::*, structs::Vault};

enum Options {
    Add_Cred = 1,
    Find_Cred = 2,
    Del_Cred = 3,
    Ls_Cred = 4,
    Sort_Cred = 5,
    Exit = 6
}

impl Options {
    pub fn print_options() -> String {
        format!(r#"
        1. Añade una credencial.
        2. Encuentra una credencial.
        3. Elimina una credencial.
        4. Muestra las credenciales almacenadas.
        5. Ordena las credenciales por servicio (alfabético).
        6. Salir.
        "#)
    }

    pub fn from_number(number: i8) -> Option<Self> {
        match number {
            1 => Some(Self::Add_Cred),
            2 => Some(Self::Find_Cred),
            3 => Some(Self::Del_Cred),
            4 => Some(Self::Ls_Cred),
            5 => Some(Self::Sort_Cred),
            6 => Some(Self::Exit),
            _ => None
        }

    }
}

pub fn menu() -> () {
    let mut vault: Vault = Vault::new();
    println!("=== RustVault - Tu Gestor de Confianza ===");

    loop {
        let choice: String = read_input(format!("Elige una opción: {} -> ", Options::print_options()).as_ref());
        let choice: Option<i8> = choice.trim().parse().ok();

        if choice.is_none() {
            println!("Valor introducido no valido, escribe el numero de la opcion que quieras.");
            continue;
        }

        let option = Options::from_number(choice.unwrap());
        if option.is_none(){
            println!("La opcion seleccionada no existe.");
            continue;
        }
        match option.unwrap() {
            Options::Add_Cred => add_cred(&mut vault),
            Options::Find_Cred => {
                loop {
                    let service = read_input("Introduce el servicio de la credencial que quieres encontrar o 0 para cancelar: ");
                    let service = service.trim();
                    if service == "0"{
                        break;
                    }
                    let cred = find_cred(&vault, &service);


                    if cred == "Credencial no encontrada"{
                        println!("Asegurate de que escribiste correctamente el servicio.");
                        continue;
                    }
                    println!("{cred}");
                    break;
                }

            },
            Options::Del_Cred => {
                let servicio = read_input("Introduce el servicio cuya credencial quieras borrar: ");
                println!("{}", del_cred(&mut vault, &servicio));
        },
        Options::Ls_Cred => println!("{}", ls_cred(&vault)),
        Options::Sort_Cred => println!("{}", sort_cred(&mut vault)),
        Options::Exit => {
            println!("Hasta Luego");
            break;
        },
        };
        
    }
}