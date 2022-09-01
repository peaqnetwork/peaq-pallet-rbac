//! peaq RBAC pallet
//!
//! The RBAC pallet allows resolving and management for  role-base access control in a generic manner.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod rbac;
mod structs;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_core::{blake2_256, Public as PublicID};
    use sp_runtime::traits::MaybeDisplay;
    use sp_std::fmt::Debug;
    use std::hash::Hash;

    use crate::{
        rbac::{RoleError, TRole, Tag},
        structs::Role,
    };

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        type RoleId: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + Ord
            + MaxEncodedLen
            + std::default::Default;
    }

    // The pallet's runtime storage items.
    // https://docs.substrate.io/main-docs/build/runtime-storage/
    #[pallet::storage]
    #[pallet::getter(fn role_of)]
    pub type RoleStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Role<T::RoleId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn owner_of)]
    pub type OwnerStore<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, [u8; 32]), T::RoleId>;

    // Pallets use events to inform users when important changes are made.
    // https://docs.substrate.io/main-docs/build/events-errors/
    #[pallet::event]
    pub enum Event<T: Config> {}

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        // Returned if the Role already exists
        RoleAlreadyExist,
        // Returned if the Role does not exists
        RoleDoesNotExist,
    }

    // Dispatchable functions allows users to interact with the pallet and invoke state changes.
    // These functions materialize as "extrinsics", which are often compared to transactions.
    // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
    #[pallet::call]
    impl<T: Config> Pallet<T> {}

    // implement the role TRole trait to satify the methods
    impl<T: Config> TRole<T::AccountId, T::RoleId> for Pallet<T> {
        fn is_owner(owner: &T::AccountId, entity: &T::RoleId) -> Result<(), RoleError> {
            let key = Self::generate_key(entity, Tag::Role);
            let key = (&owner, &key).using_encoded(blake2_256);

            // Check if attribute already exists
            if !<OwnerStore<T>>::contains_key((&owner, &key)) {
                return Err(RoleError::RoleAuthorizationFailed);
            }

            Ok(())
        }

        fn create() -> Result<(), RoleError> {
            todo!()
        }

        fn delete() -> Result<(), RoleError> {
            todo!()
        }

        fn generate_key(entity: &T::RoleId, tag: Tag) -> [u8; 32] {
            let mut bytes_in_name: Vec<u8> = tag.to_string().as_bytes().to_vec();
            let mut bytes_to_hash: Vec<u8> = entity.encode().as_slice().to_vec();
            bytes_to_hash.append(&mut bytes_in_name);
            blake2_256(&bytes_to_hash[..])
        }
    }
}
