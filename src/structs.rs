use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Default, TypeInfo, Decode, Encode, RuntimeDebug,
)]
pub struct Role<RoleId> {
    pub id: RoleId,
    pub name: Vec<u8>,
}
