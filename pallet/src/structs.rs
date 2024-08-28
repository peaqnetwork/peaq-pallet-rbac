use crate::MAX_NAME_SIZE;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::ConstU32;
use frame_support::BoundedVec;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::RuntimeDebug;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    TypeInfo,
    Decode,
    Encode,
    RuntimeDebug,
    MaxEncodedLen,
)]
pub struct Entity<EntityId> {
    pub id: EntityId,
    pub name: BoundedVec<u8, ConstU32<{ MAX_NAME_SIZE as u32 }>>,
    pub enabled: bool,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    TypeInfo,
    Decode,
    Encode,
    RuntimeDebug,
    MaxEncodedLen,
)]
pub struct Role2User<EntityId> {
    pub role: EntityId,
    pub user: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    TypeInfo,
    Decode,
    Encode,
    RuntimeDebug,
    MaxEncodedLen,
)]
pub struct Role2Group<EntityId> {
    pub role: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    TypeInfo,
    Decode,
    Encode,
    RuntimeDebug,
    MaxEncodedLen,
)]
pub struct User2Group<EntityId> {
    pub user: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    TypeInfo,
    Decode,
    Encode,
    RuntimeDebug,
    MaxEncodedLen,
)]
pub struct Permission2Role<EntityId> {
    pub permission: EntityId,
    pub role: EntityId,
}
