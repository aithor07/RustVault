use std::io::{self, Write, stdout, stdin};
use crate::structs::*;
use colored::Colorize;

pub fn read_input(prompt: &str) -> String {
    print!("{prompt}");
    stdout().flush().expect("Ocurrio un error al flushear");

    let mut input: String = String::new();

    stdin().read_line(&mut input).expect("Error al leer el input");

    input.trim().to_string()
}





pub fn add_cred(vault: &mut Vault) -> () {
    let service = read_input("Introduce el servicio al que pertenece la credencial: ");
    let username: String = read_input("Introduce el usuario o correo de la credencial: ");
    let password: String = read_input("Introduce la contraseña de la credencial: ");

    let cred = Credential { service, username, password };
    vault.add(cred);
    println!("{}", "\n\n\nCredencial añadida con exito!\n\n\n".green());
}

pub fn find_cred(vault: &Vault, service: &str) -> String {
    let credential = vault.find(service);

    if credential.is_none(){
        return "Credencial no encontrada".red().to_string();
    }
    credential.unwrap().to_string()
}


pub fn ls_cred(vault: &Vault) -> String {
    vault.list_all()
}

pub fn del_cred(vault: &mut Vault, service: &str) -> String {
    let removed = vault.remove(service);
    if removed.is_none(){
        return "No se encontro esa credencial para borrar".to_string()
    }
    removed.unwrap().to_string()
}

pub fn sort_cred(vault: &mut Vault) -> String {
    vault.sort();
    vault.list_all()
}