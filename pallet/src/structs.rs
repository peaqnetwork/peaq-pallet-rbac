use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug //, Serialize, Deserialize
)]
pub struct Entity<EntityId> {
    pub id: EntityId,
    pub name: Vec<u8>,
    pub enabled: bool,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug //, Serialize, Deserialize
)]
pub struct Role2User<EntityId> {
    pub role: EntityId,
    pub user: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug //, Serialize, Deserialize
)]
pub struct Role2Group<EntityId> {
    pub role: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug //, Serialize, Deserialize
)]
pub struct User2Group<EntityId> {
    pub user: EntityId,
    pub group: EntityId,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug //, Serialize, Deserialize
)]
pub struct Permission2Role<EntityId> {
    pub permission: EntityId,
    pub role: EntityId,
}
