//represents a credential
pub struct Credential {
    pub service: String,
    pub username: String,
    pub password: String
}

impl Credential {
    pub fn new(service: String, username: String) -> Self {
        Self { service, username, password: String::from("placeholder") }
    }
    pub fn to_string(&self) -> String {
        format!(r#"
        Servicio: {} - Usuario: {} - Contraseña: {}
        "#, self.service, self.username, self.password)
    }

}


//-------------------------------------------------------------------



//Stores credentials in a vector
pub struct Vault {
    credentials: Vec<Credential>
}

impl Vault {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new()
         }
    }

    pub fn count(&self) -> usize {
        self.credentials.len()
    }

    pub fn add(&mut self, credential: Credential) -> Option<bool> {
        let curr_len: usize = self.count();
        self.credentials.push(credential);
        if (curr_len != self.count()){
            return Some(true);
        }
        None
    }

    pub fn find(&self, service: &str) -> Option<&Credential> {
        self.credentials.iter().find(|&c| c.service == service)
    }

    pub fn remove(&mut self, service: &str) -> Option<Credential> {
        let del_index: usize = self.credentials.iter().position(|c| c.service == service)?;
        Some(self.credentials.swap_remove(del_index))
    }

    pub fn sort(&mut self) -> (){
        self.credentials.sort_by(|a, b| {
            a.service.cmp(&b.service)
        });
    }

    pub fn list_all(&self) -> String {
    let mut result = String::new();

    self.credentials.iter().for_each(|c| {
        result.push_str(&format!(
            "Servicio: {} - Usuario: {} - Contraseña: {}\n",
            c.service, c.username, c.password
        ));
    });

    result
}


}