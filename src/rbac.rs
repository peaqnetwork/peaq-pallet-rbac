use crate::structs::*;
use sp_std::vec::Vec;

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
    fn generate_key(entity: &EntityId, tag: Tag) -> [u8; 32];
    fn is_owner(owner: &AccountId, key: &[u8; 32]) -> Result<(), EntityError>;
    fn get_user_roles(user_id: EntityId) -> Option<Vec<Role2User<EntityId>>>;
    fn get_group_roles(group_id: EntityId) -> Option<Vec<Role2Group<EntityId>>>;
    fn get_role_permissions(role_id: EntityId) -> Option<Vec<Permission2Role<EntityId>>>;
    fn create_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user_id: EntityId,
    ) -> Result<(), EntityError>;
    fn revoke_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user_id: EntityId,
    ) -> Result<(), EntityError>;
    fn create_role_to_group(
        owner: &AccountId,
        role_id: EntityId,
        group_id: EntityId,
    ) -> Result<(), EntityError>;
    fn revoke_role_to_group(
        owner: &AccountId,
        role_id: EntityId,
        group_id: EntityId,
    ) -> Result<(), EntityError>;
    fn create_user_to_group(
        owner: &AccountId,
        user_id: EntityId,
        group_id: EntityId,
    ) -> Result<(), EntityError>;
    fn revoke_user_to_group(
        owner: &AccountId,
        user_id: EntityId,
        group_id: EntityId,
    ) -> Result<(), EntityError>;
    fn create_permission_to_role(
        owner: &AccountId,
        permission_id: EntityId,
        role_id: EntityId,
    ) -> Result<(), EntityError>;
    fn revoke_permission_to_role(
        owner: &AccountId,
        permission_id: EntityId,
        role_id: EntityId,
    ) -> Result<(), EntityError>;
}

pub trait Role<AccountId, EntityId> {
    fn get_role(role_id: EntityId) -> Option<Entity<EntityId>>;
    fn get_roles() -> Vec<Entity<EntityId>>;
    fn create_role(owner: &AccountId, role_id: EntityId, name: &[u8]) -> Result<(), EntityError>;
    fn update_existing_role(
        owner: &AccountId,
        role_id: EntityId,
        name: &[u8],
    ) -> Result<(), EntityError>;
    fn disable_existing_role(owner: &AccountId, role_id: EntityId) -> Result<(), EntityError>;
}

pub trait Permission<AccountId, EntityId> {
    fn get_permission(permission_id: EntityId) -> Option<Entity<EntityId>>;
    fn get_permissions() -> Vec<Entity<EntityId>>;
    fn create_permission(
        owner: &AccountId,
        permission_id: EntityId,
        name: &[u8],
    ) -> Result<(), EntityError>;
    fn update_existing_permission(
        owner: &AccountId,
        permission_id: EntityId,
        name: &[u8],
    ) -> Result<(), EntityError>;
    fn disable_existing_permission(
        owner: &AccountId,
        permission_id: EntityId,
    ) -> Result<(), EntityError>;
}

pub trait Group<AccountId, EntityId> {
    fn get_group(group_id: EntityId) -> Option<Entity<EntityId>>;
    fn get_groups() -> Vec<Entity<EntityId>>;
    fn create_group(owner: &AccountId, group_id: EntityId, name: &[u8]) -> Result<(), EntityError>;
    fn update_existing_group(
        owner: &AccountId,
        group_id: EntityId,
        name: &[u8],
    ) -> Result<(), EntityError>;
    fn disable_existing_group(owner: &AccountId, group_id: EntityId) -> Result<(), EntityError>;
}

pub enum Tag {
    Role,
    Group,
    Role2User,
    Role2Group,
    User2Group,
    Permission,
    Permission2Role,
}

impl Tag {
    pub fn to_string(&self) -> &str {
        match self {
            Self::Role => "Role",
            Self::Group => "Group",
            Self::Role2User => "R2U",
            Self::Role2Group => "R2G",
            Self::User2Group => "U2G",
            Self::Permission => "Permission",
            Self::Permission2Role => "P2R",
        }
    }
}
