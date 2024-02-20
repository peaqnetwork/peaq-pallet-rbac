use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Entity<EntityId> {
    pub id: EntityId,
    pub name: Vec<u8>,
    pub enabled: bool,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Role2User<EntityId> {
    pub role: EntityId,
    pub user: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Role2Group<EntityId> {
    pub role: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct User2Group<EntityId> {
    pub user: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Permission2Role<EntityId> {
    pub permission: EntityId,
    pub role: EntityId,
}
