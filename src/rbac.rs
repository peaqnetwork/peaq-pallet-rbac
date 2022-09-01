pub enum RoleError {
    // Returned if the Role already exists
    RoleAlreadyExist,
    // Returned if the Role does not exists
    RoleDoesNotExist,
    // Returned if the Role does not belong to the caller
    RoleAuthorizationFailed,
}

pub trait TRole<AccountId, RoleId> {
    fn is_owner(owner: &AccountId, entity: &RoleId) -> Result<(), RoleError>;
    fn create() -> Result<(), RoleError>;
    fn delete() -> Result<(), RoleError>;
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
