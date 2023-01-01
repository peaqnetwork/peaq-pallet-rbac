#![cfg_attr(not(feature = "std"), no_std)]
// The `too_many_arguments` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::too_many_arguments)]
// The `unnecessary_mut_passed` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::unnecessary_mut_passed)]

use codec::Codec;
use peaq_pallet_rbac::structs::{Entity, Role2User, Role2Group, Permission2Role, User2Group};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait PeaqRBACRuntimeApi<AccountId, EntityId>
    where
        AccountId: Codec,
        EntityId: Codec
    {
        fn fetch_role(account: AccountId, entity: EntityId) -> Option<Entity<EntityId>>;

        fn fetch_roles(owner: AccountId) -> Vec<Entity<EntityId>>;

        fn fetch_user_roles(owner: AccountId, user_id: EntityId) -> Option<Vec<Role2User<EntityId>>>;

        fn fetch_permission(owner: AccountId, permission_id: EntityId) -> Option<Entity<EntityId>>;

        fn fetch_permissions(owner: AccountId) -> Vec<Entity<EntityId>>;

        fn fetch_role_permissions(owner: AccountId, role_id: EntityId) -> Option<Vec<Permission2Role<EntityId>>>;

        fn fetch_group(owner: AccountId, group_id: EntityId) -> Option<Entity<EntityId>>;

        fn fetch_groups(owner: AccountId) -> Vec<Entity<EntityId>>;

        fn fetch_group_roles(owner: AccountId, group_id: EntityId) -> Option<Vec<Role2Group<EntityId>>>;
        
        fn fetch_user_groups(owner: AccountId, user_id: EntityId) -> Option<Vec<User2Group<EntityId>>>;

        fn fetch_user_permissions(owner: AccountId, user_id: EntityId) -> Option<Vec<Entity<EntityId>>>;
        
        fn fetch_group_permissions(owner: AccountId, group_id: EntityId) -> Option<Vec<Entity<EntityId>>>;
    }
}