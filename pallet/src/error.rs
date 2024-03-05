use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_std::vec::Vec;

/// Result definition for RBAC pallet with unique error type
pub type Result<T, RbacError> = core::result::Result<T, RbacError>;

/// All possible user error types of the RBAC pallet than can occur, when passing
/// wrong or invalid parameters. Must be serialize-able when used via RPC.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Encode, Decode, TypeInfo)]
pub enum RbacErrorType {
    /// Returned if the Entity already exists
    EntityAlreadyExist,
    /// Returned if the Entity does not exists
    EntityDoesNotExist,
    /// Returned if the Entity does not belong to the caller
    EntityAuthorizationFailed,
    /// Returned if the Entity is not enabled
    EntityDisabled,
    /// Returned if an assignment does already exist
    AssignmentAlreadyExist,
    /// Returned if an assignment does not exist
    AssignmentDoesNotExist,
    /// Exceeds max characters
    NameExceedMaxChar,
    /// Exceeds BoundedLen bounds
    StorageExceedsMaxBounds
}

/// Struct encapsules all informations about occured error: error type and passed
/// data which lead to that error. Must be serialize-able when used via RPC.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Encode, Decode, TypeInfo)]
pub struct RbacError {
    /// type of error, see RbacErrorType
    pub typ: RbacErrorType,
    /// passed id/name which lead to that error in bytes
    pub param: Vec<u8>,
}

impl RbacError {
    /// generates a new RbacError including Result
    pub fn err<T, EntityId: Parameter>(
        typ: RbacErrorType,
        data: &EntityId,
    ) -> Result<T, RbacError> {
        // this transformation makes it possible to use RbacError without generic
        let param = data.encode().as_slice().to_vec();
        Err(RbacError { typ, param })
    }
}
