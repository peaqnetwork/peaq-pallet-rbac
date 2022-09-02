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
pub mod rbac;
pub mod structs;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    use sp_std::fmt::Debug;
    use sp_std::vec::Vec;

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
            + Clone
            + Copy
            + MaxEncodedLen
            + Default;
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
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event emitted when a role has been added. [who, roleId, entityName]
        RoleAdded(T::AccountId, T::RoleId, Vec<u8>),
        RoleUpdated(T::AccountId, T::RoleId, Vec<u8>),
        /// Event emitted when a role has been added. [who, roleId]
        RoleRemoved(T::AccountId, T::RoleId),
        RoleFetched(Role<T::RoleId>),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        // Name exceeds 64
        EntityNameExceedMax64,
        // Returned if the Role already exists
        RoleAlreadyExist,
        // Returned if the Role does not exists
        RoleDoesNotExist,
        // Failed to verify entity ownership
        EntityAuthorizationFailed,
    }

    impl<T: Config> Error<T> {
        fn dispatch_error(err: RoleError) -> DispatchResult {
            match err {
                RoleError::RoleAlreadyExist => return Err(Error::<T>::RoleAlreadyExist.into()),
                RoleError::RoleDoesNotExist => return Err(Error::<T>::RoleDoesNotExist.into()),
                RoleError::NameExceedMaxChar => {
                    return Err(Error::<T>::EntityNameExceedMax64.into())
                }
                RoleError::RoleAuthorizationFailed => {
                    return Err(Error::<T>::EntityAuthorizationFailed.into())
                }
            }
        }
    }

    // Dispatchable functions allows users to interact with the pallet and invoke state changes.
    // These functions materialize as "extrinsics", which are often compared to transactions.
    // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(1_000)]
        pub fn fetch_role(origin: OriginFor<T>, entity: T::RoleId) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            ensure_signed(origin)?;
            let role = Self::fetch(entity);

            match role {
                Some(role) => {
                    Self::deposit_event(Event::RoleFetched(role));
                }
                None => return Err(Error::<T>::RoleDoesNotExist.into()),
            };

            Ok(())
        }

        /// create role call
        #[pallet::weight(1_000)]
        pub fn add_role(origin: OriginFor<T>, entity: T::RoleId, name: Vec<u8>) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::create(&sender, entity, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleAdded(sender, entity, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// update role call
        #[pallet::weight(1_000)]
        pub fn update_role(
            origin: OriginFor<T>,
            entity: T::RoleId,
            name: Vec<u8>,
        ) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::update(&sender, entity, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleUpdated(sender, entity, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        #[pallet::weight(1_000)]
        pub fn remove_role(origin: OriginFor<T>, entity: T::RoleId) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            let sender = ensure_signed(origin)?;

            match Self::delete(&sender, entity) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleRemoved(sender, entity));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }
    }

    // implement the role TRole trait to satify the methods
    impl<T: Config> TRole<T::AccountId, T::RoleId> for Pallet<T> {
        fn is_owner(owner: &T::AccountId, entity: &T::RoleId) -> Result<(), RoleError> {
            let key = Self::generate_key(entity, Tag::Role);
            let key = (&owner, &key).using_encoded(blake2_256);

            // Check if role already exists
            if !<OwnerStore<T>>::contains_key((&owner, &key)) {
                return Err(RoleError::RoleAuthorizationFailed);
            }

            Ok(())
        }

        fn fetch(entity: T::RoleId) -> Option<Role<T::RoleId>> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            if <RoleStore<T>>::contains_key(&key) {
                return Some(Self::role_of(&key));
            }
            None
        }

        fn create(owner: &T::AccountId, entity: T::RoleId, name: &[u8]) -> Result<(), RoleError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // Check if role already exists
            if <RoleStore<T>>::contains_key(&key) {
                return Err(RoleError::RoleAlreadyExist);
            }

            let new_role = Role {
                id: entity,
                name: (&name).to_vec(),
            };

            <RoleStore<T>>::insert(&key, new_role);

            // Store the owner of the role for further validation
            // when modification is requested
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), entity.clone());

            Ok(())
        }

        fn update(owner: &T::AccountId, entity: T::RoleId, name: &[u8]) -> Result<(), RoleError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // check ownership
            let is_owner = Self::is_owner(owner, &entity);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&key) {
                return Err(RoleError::RoleDoesNotExist);
            }

            // Get role
            let role = Self::fetch(entity);

            match role {
                Some(mut role) => {
                    role.name = (&name).to_vec();

                    <RoleStore<T>>::mutate(&key, |a| *a = role);
                    Ok(())
                }
                None => Err(RoleError::RoleDoesNotExist),
            }
        }

        fn delete(owner: &T::AccountId, entity: T::RoleId) -> Result<(), RoleError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // check ownership
            let is_owner = Self::is_owner(owner, &entity);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&key) {
                return Err(RoleError::RoleDoesNotExist);
            }

            <RoleStore<T>>::remove(&key);

            // Remove the ownership of the role
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::remove((&owner, &key));

            Ok(())
        }

        fn generate_key(entity: &T::RoleId, tag: Tag) -> [u8; 32] {
            let mut bytes_in_name: Vec<u8> = tag.to_string().as_bytes().to_vec();
            let mut bytes_to_hash: Vec<u8> = entity.encode().as_slice().to_vec();
            bytes_to_hash.append(&mut bytes_in_name);
            blake2_256(&bytes_to_hash[..])
        }
    }
}
