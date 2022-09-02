use crate::structs::*;

pub enum RoleError {
    // Returned if the Role already exists
    RoleAlreadyExist,
    // Returned if the Role does not exists
    RoleDoesNotExist,
    // Returned if the Role does not belong to the caller
    RoleAuthorizationFailed,
    // Exceeds max characters
    NameExceedMaxChar,
}

pub trait TRole<AccountId, RoleId> {
    fn is_owner(owner: &AccountId, entity: &RoleId) -> Result<(), RoleError>;
    fn fetch(entity: RoleId) -> Option<Role<RoleId>>;
    fn create(owner: &AccountId, entity: RoleId, name: &[u8]) -> Result<(), RoleError>;
    fn update(owner: &AccountId, entity: RoleId, name: &[u8]) -> Result<(), RoleError>;
    fn delete(owner: &AccountId, entity: RoleId) -> Result<(), RoleError>;
    fn generate_key(entity: &RoleId, tag: Tag) -> [u8; 32];
}

pub enum Tag {
    Role,
}

impl Tag {
    pub fn to_string(&self) -> &str {
        match self {
            Self::Role => "Role",
        }
    }
}
