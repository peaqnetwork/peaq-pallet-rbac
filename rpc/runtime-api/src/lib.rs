#![cfg_attr(not(feature = "std"), no_std)]
// The `too_many_arguments` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::too_many_arguments)]
// The `unnecessary_mut_passed` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::unnecessary_mut_passed)]

use codec::Codec;
use peaq_pallet_rbac::{
    rbac::Result as RbacResult,
    structs::{Entity, Permission2Role, Role2Group, Role2User, User2Group},
};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait PeaqRBACRuntimeApi<AccountId, EntityId>
    where
        AccountId: Codec,
        EntityId: Codec
    {
        fn fetch_role(account: AccountId, entity: EntityId) -> RbacResult<Entity<EntityId>>;

        fn fetch_roles(owner: AccountId) -> RbacResult<Vec<Entity<EntityId>>>;

        fn fetch_user_roles(owner: AccountId, user_id: EntityId) -> RbacResult<Vec<Role2User<EntityId>>>;

        fn fetch_permission(owner: AccountId, permission_id: EntityId) -> RbacResult<Entity<EntityId>>;

        fn fetch_permissions(owner: AccountId) -> RbacResult<Vec<Entity<EntityId>>>;

        fn fetch_role_permissions(owner: AccountId, role_id: EntityId) -> RbacResult<Vec<Permission2Role<EntityId>>>;

        fn fetch_group(owner: AccountId, group_id: EntityId) -> RbacResult<Entity<EntityId>>;

        fn fetch_groups(owner: AccountId) -> RbacResult<Vec<Entity<EntityId>>>;

        fn fetch_group_roles(owner: AccountId, group_id: EntityId) -> RbacResult<Vec<Role2Group<EntityId>>>;

        fn fetch_user_groups(owner: AccountId, user_id: EntityId) -> RbacResult<Vec<User2Group<EntityId>>>;

        fn fetch_user_permissions(owner: AccountId, user_id: EntityId) -> RbacResult<Vec<Entity<EntityId>>>;

        fn fetch_group_permissions(owner: AccountId, group_id: EntityId) -> RbacResult<Vec<Entity<EntityId>>>;
    }
}
