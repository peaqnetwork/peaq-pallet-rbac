#![cfg_attr(not(feature = "std"), no_std)]
// The `too_many_arguments` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::too_many_arguments)]
// The `unnecessary_mut_passed` warning originates from `decl_runtime_apis` macro.
#![allow(clippy::unnecessary_mut_passed)]

use codec::Codec;
use peaq_pallet_rbac::structs::Entity;

sp_api::decl_runtime_apis! {
    pub trait PeaqRBACApi<OriginFor, AccountId, EntityId>
    where
        OriginFor: Codec,
        AccountId: Codec,
        EntityId: Codec
    {
        fn read(owner: OriginFor, did_account: AccountId, entity: EntityId) -> Option<Entity<EntityId>>;
    }
}