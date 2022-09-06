use crate::structs::*;

pub enum EntityError {
    // Returned if the Entity already exists
    EntityAlreadyExist,
    // Returned if the Entity does not exists
    EntityDoesNotExist,
    // Returned if the Entity does not belong to the caller
    EntityAuthorizationFailed,
    // Exceeds max characters
    NameExceedMaxChar,
}

pub trait Rbac<AccountId, EntityId> {
    fn check_has_role(role_id: EntityId, entity_id: EntityId) -> Option<Role2User<EntityId>>;
    fn create_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user: EntityId,
    ) -> Result<(), EntityError>;
    fn delete_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user: EntityId,
    ) -> Result<(), EntityError>;
}

pub trait Entity<AccountId, EntityId> {
    fn generate_key(entity: &EntityId, tag: Tag) -> [u8; 32];
    fn generate_relationship_key(entity: &EntityId, related_to: &EntityId, tag: Tag) -> [u8; 32];
    fn is_owner(owner: &AccountId, key: &[u8; 32]) -> Result<(), EntityError>;
    fn fetch(entity: EntityId) -> Option<Role<EntityId>>;
    fn create(owner: &AccountId, entity: EntityId, name: &[u8]) -> Result<(), EntityError>;
    fn update(owner: &AccountId, entity: EntityId, name: &[u8]) -> Result<(), EntityError>;
    fn delete(owner: &AccountId, entity: EntityId) -> Result<(), EntityError>;
}

pub enum Tag {
    Role,
    Role2User,
}

impl Tag {
    pub fn to_string(&self) -> &str {
        match self {
            Self::Role => "Role",
            Self::Role2User => "R2U",
        }
    }
}
