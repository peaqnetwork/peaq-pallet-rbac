use crate::structs::*;
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sp_std::vec::Vec;

pub type Result<T> = std::result::Result<T, EntityError>;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Encode, Decode)]
pub enum EntityError {
    // Returned if the Entity already exists
    EntityAlreadyExist,
    // Returned if the Entity does not exists
    EntityDoesNotExist,
    // Returned if the Entity does not belong to the caller
    EntityAuthorizationFailed,
    // Returned if the Entity is not enabled
    EntityDisabled,
    // Exceeds max characters
    NameExceedMaxChar,
}

pub trait Rbac<AccountId, EntityId> {
    fn generate_key(
        owner: &AccountId,
        entity: &EntityId,
        tag: Tag
    ) -> [u8; 32];

    fn get_entity(
        key: [u8; 32]
    ) -> Result<Entity<EntityId>>;
    
    // fn check_entity_exists(
    //     key: [u8; 32]
    // ) -> bool;

    fn get_user_roles(
        owner: &AccountId,
        user_id: EntityId
    ) -> Result<Vec<Role2User<EntityId>>>;
    
    fn get_user_groups(
        owner: &AccountId,
        user_id: EntityId
    ) -> Result<Vec<User2Group<EntityId>>>;
    
    fn get_group_roles(
        owner: &AccountId,
        group_id: EntityId
    ) -> Result<Vec<Role2Group<EntityId>>>;
    
    fn get_role_permissions(
        owner: &AccountId,
        role_id: EntityId,
    ) -> Result<Vec<Permission2Role<EntityId>>>;
    
    fn get_user_permissions(
        owner: &AccountId,
        user_id: EntityId
    ) -> Result<Vec<Entity<EntityId>>>;
    
    fn get_group_permissions(
        owner: &AccountId,
        group_id: EntityId,
    ) -> Result<Vec<Entity<EntityId>>>;
    
    fn create_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user_id: EntityId,
    ) -> Result<()>;
    
    fn revoke_role_to_user(
        owner: &AccountId,
        role_id: EntityId,
        user_id: EntityId,
    ) -> Result<()>;
    
    fn create_role_to_group(
        owner: &AccountId,
        role_id: EntityId,
        group_id: EntityId,
    ) -> Result<()>;
    
    fn revoke_role_to_group(
        owner: &AccountId,
        role_id: EntityId,
        group_id: EntityId,
    ) -> Result<()>;
    
    fn create_user_to_group(
        owner: &AccountId,
        user_id: EntityId,
        group_id: EntityId,
    ) -> Result<()>;
    
    fn revoke_user_to_group(
        owner: &AccountId,
        user_id: EntityId,
        group_id: EntityId,
    ) -> Result<()>;
    
    fn create_permission_to_role(
        owner: &AccountId,
        permission_id: EntityId,
        role_id: EntityId,
    ) -> Result<()>;
    
    fn revoke_permission_to_role(
        owner: &AccountId,
        permission_id: EntityId,
        role_id: EntityId,
    ) -> Result<()>;
}

pub trait Role<AccountId, EntityId> {
    fn get_role(
        owner: &AccountId,
        role_id: EntityId
    ) -> Result<Entity<EntityId>>;
    
    fn get_roles(
        owner: &AccountId
    ) -> Result<Vec<Entity<EntityId>>>;
    
    fn create_role(
        owner: &AccountId,
        role_id: EntityId,
        name: &[u8]
    ) -> Result<()>;
    
    fn update_existing_role(
        owner: &AccountId,
        role_id: EntityId,
        name: &[u8],
    ) -> Result<()>;
    
    fn disable_existing_role(
        owner: &AccountId,
        role_id: EntityId
    ) -> Result<()>;
}

pub trait Permission<AccountId, EntityId> {
    fn get_permission(
        owner: &AccountId,
        permission_id: EntityId
    ) -> Result<Entity<EntityId>>;
    
    fn get_permissions(
        owner: &AccountId
    ) -> Result<Vec<Entity<EntityId>>>;
    
    fn create_permission(
        owner: &AccountId,
        permission_id: EntityId,
        name: &[u8],
    ) -> Result<()>;
    
    fn update_existing_permission(
        owner: &AccountId,
        permission_id: EntityId,
        name: &[u8],
    ) -> Result<()>;
    
    fn disable_existing_permission(
        owner: &AccountId,
        permission_id: EntityId,
    ) -> Result<()>;
}

pub trait Group<AccountId, EntityId> {
    fn get_group(
        owner: &AccountId,
        group_id: EntityId
    ) -> Result<Entity<EntityId>>;
    
    fn get_groups(
        owner: &AccountId
    ) -> Result<Vec<Entity<EntityId>>>;
    
    fn create_group(
        owner: &AccountId,
        group_id: EntityId,
        name: &[u8]
    ) -> Result<()>;
    
    fn update_existing_group(
        owner: &AccountId,
        group_id: EntityId,
        name: &[u8],
    ) -> Result<()>;
    
    fn disable_existing_group(
        owner: &AccountId,
        group_id: EntityId
    ) -> Result<()>;
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
