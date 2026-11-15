use crate::{
    credential::{Credential, CredentialSummary, NewCredential},
    database::SqliteCredentialRepository,
    error::Result,
};

pub struct Vault {
    repository: SqliteCredentialRepository,
}

impl Vault {
    pub fn new(repository: SqliteCredentialRepository) -> Self {
        Self { repository }
    }

    pub fn add_credential(&self, credential: &NewCredential) -> Result<()> {
        match self.repository.add(credential) {
            Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn find_credential(&self, service: &str, username: &str) -> Result<Option<Credential>> {
        match self.repository.find(service, username) {
            Ok(credential) => Ok(credential),
            Err(error) => Err(error),
        }
    }

    pub fn list_all_credentials(&self) -> Result<Vec<CredentialSummary>> {
        match self.repository.list_all() {
            Ok(credentials) => Ok(credentials),
            Err(error) => Err(error),
        }
    }

    pub fn delete_credential(
        &self,
        id: Option<i64>,
        service: &str,
        username: &str,
    ) -> Result<bool> {
        match self.repository.delete(id, service, username) {
            Ok(deleted) => Ok(deleted),
            Err(error) => Err(error),
        }
    }

    pub fn list_credentials_sorted(&self) -> Result<Vec<CredentialSummary>> {
        match self.repository.list_sorted() {
            Ok(credentials) => Ok(credentials),
            Err(error) => Err(error),
        }
    }

    pub fn count_credentials(&self) -> Result<i64> {
        match self.repository.count() {
            Ok(count) => Ok(count),
            Err(error) => Err(error),
        }
    }
}
