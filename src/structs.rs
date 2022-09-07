use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Entity<EntityId> {
    pub id: EntityId,
    pub name: Vec<u8>,
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Role2User<EntityId> {
    pub role: EntityId,
    pub user: EntityId,
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Permission2Role<EntityId: Encode> {
    pub permission: EntityId,
    pub role: EntityId,
}

pub struct Stores {}
