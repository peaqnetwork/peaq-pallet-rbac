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
    use codec::{Encode, MaxEncodedLen};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    use sp_std::fmt::Debug;
    use sp_std::vec::Vec;

    use crate::{
        rbac::{EntityError, Permission, Rbac, Role, Tag},
        structs::{Entity, Role2User},
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
        type EntityId: Parameter
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
        StorageMap<_, Blake2_128Concat, [u8; 32], Entity<T::EntityId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn owner_of)]
    pub type OwnerStore<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, [u8; 32]), T::EntityId>;

    #[pallet::storage]
    #[pallet::getter(fn rbac_of)]
    pub type RbacStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Role2User<T::EntityId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permission_of)]
    pub type PermissionStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Entity<T::EntityId>, ValueQuery>;

    // Pallets use events to inform users when important changes are made.
    // https://docs.substrate.io/main-docs/build/events-errors/
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event emitted when a role has been added. [who, roleId, roleName]
        RoleAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a role has been updated. [who, roleId, roleName]
        RoleUpdated(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a role has been added. [who, roleId]
        RoleRemoved(T::AccountId, T::EntityId),
        RoleFetched(Entity<T::EntityId>),
        /// Event emitted when a role has been assigned to user. [who, roleId, userId]
        RoleAssigned(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a role has been removed from user. [who, roleId, userId]
        RoleRemovedFromUser(T::AccountId, T::EntityId, T::EntityId),
        HasRole(Role2User<T::EntityId>),

        /// Event emitted when a permission has been added. [who, permissionId, permissionName]
        PermissionAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a permission has been updated. [who, permissionId, permissionName]
        PermissionUpdated(T::AccountId, T::EntityId, Vec<u8>),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        // Name exceeds 64
        EntityNameExceedMax64,
        // Returned if the Role already exists
        EntityAlreadyExist,
        // Returned if the Role does not exists
        EntityDoesNotExist,
        // Failed to verify entity ownership
        EntityAuthorizationFailed,
    }

    impl<T: Config> Error<T> {
        fn dispatch_error(err: EntityError) -> DispatchResult {
            match err {
                EntityError::EntityAlreadyExist => {
                    return Err(Error::<T>::EntityAlreadyExist.into())
                }
                EntityError::EntityDoesNotExist => {
                    return Err(Error::<T>::EntityDoesNotExist.into())
                }
                EntityError::NameExceedMaxChar => {
                    return Err(Error::<T>::EntityNameExceedMax64.into())
                }
                EntityError::EntityAuthorizationFailed => {
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
        pub fn fetch_role(origin: OriginFor<T>, entity: T::EntityId) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            ensure_signed(origin)?;
            let role = Self::get_role(entity);

            match role {
                Some(role) => {
                    Self::deposit_event(Event::RoleFetched(role));
                }
                None => return Err(Error::<T>::EntityDoesNotExist.into()),
            };

            Ok(())
        }

        /// create role call
        #[pallet::weight(1_000)]
        pub fn add_role(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::create_role(&sender, role_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleAdded(sender, role_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// update role call
        #[pallet::weight(1_000)]
        pub fn update_role(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::update_existing_role(&sender, role_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleUpdated(sender, role_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        #[pallet::weight(1_000)]
        pub fn remove_role(origin: OriginFor<T>, role_id: T::EntityId) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::delete_role(&sender, role_id) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleRemoved(sender, role_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        #[pallet::weight(1_000)]
        pub fn has_role(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let role_to_user = Self::check_has_role(role_id, user_id);

            match role_to_user {
                Some(r2u) => {
                    Self::deposit_event(Event::HasRole(r2u));
                }
                None => return Err(Error::<T>::EntityDoesNotExist.into()),
            };

            Ok(())
        }

        /// assign a role to user call
        #[pallet::weight(1_000)]
        pub fn assign_role_to_user(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::create_role_to_user(&sender, role_id, user_id) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleAssigned(sender, role_id, user_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// remove role to user relationship call
        #[pallet::weight(1_000)]
        pub fn remove_role_to_user(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::delete_role_to_user(&sender, role_id, user_id) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleRemovedFromUser(sender, role_id, user_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// create permission call
        #[pallet::weight(1_000)]
        pub fn add_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::create_permission(&sender, permission_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::PermissionAdded(sender, permission_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// update permission call
        #[pallet::weight(1_000)]
        pub fn update_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::update_existing_permission(&sender, permission_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::PermissionUpdated(sender, permission_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }
    }
    // implement the Rbac trait to satify the methods
    impl<T: Config> Rbac<T::AccountId, T::EntityId> for Pallet<T> {
        fn check_has_role(
            role_id: T::EntityId,
            entity_id: T::EntityId,
        ) -> Option<Role2User<T::EntityId>> {
            // Generate key for integrity check
            let key = Self::generate_relationship_key(&role_id, &entity_id, Tag::Role2User);

            if <RbacStore<T>>::contains_key(&key) {
                return Some(Self::rbac_of(&key));
            }
            None
        }
        fn create_role_to_user(
            owner: &T::AccountId,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let role_key = Self::generate_key(&role_id, Tag::Role);
            let role_2_user_key =
                Self::generate_relationship_key(&role_id, &user_id, Tag::Role2User);

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&role_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check role ownership
            let is_owner = Self::is_owner(owner, &role_key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // Check if role has already been assigned to user
            if <RbacStore<T>>::contains_key(&role_2_user_key) {
                return Err(EntityError::EntityAlreadyExist);
            }

            let new_assign = Role2User {
                role: role_id,
                user: user_id,
            };

            <RbacStore<T>>::insert(&role_2_user_key, new_assign);

            // Store the owner of the role assignment for further validation
            // when modification is requested
            let key = (&owner, &role_2_user_key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), user_id.clone());

            Ok(())
        }

        fn delete_role_to_user(
            owner: &T::AccountId,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let role_2_user_key =
                Self::generate_relationship_key(&role_id, &user_id, Tag::Role2User);

            // Check if role exists
            if !<RbacStore<T>>::contains_key(&role_2_user_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &role_2_user_key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            <RbacStore<T>>::remove(&role_2_user_key);

            // Remove the ownership of the role
            let key = (&owner, &role_2_user_key).using_encoded(blake2_256);
            <OwnerStore<T>>::remove((&owner, &key));

            Ok(())
        }
        fn is_owner(owner: &T::AccountId, key: &[u8; 32]) -> Result<(), EntityError> {
            let key = (&owner, &key).using_encoded(blake2_256);

            // Check if role already exists
            if !<OwnerStore<T>>::contains_key((owner, key)) {
                return Err(EntityError::EntityAuthorizationFailed);
            }

            Ok(())
        }

        fn generate_key(entity: &T::EntityId, tag: Tag) -> [u8; 32] {
            let mut bytes_in_tag: Vec<u8> = tag.to_string().as_bytes().to_vec();
            let mut bytes_to_hash: Vec<u8> = entity.encode().as_slice().to_vec();
            bytes_to_hash.append(&mut bytes_in_tag);
            blake2_256(&bytes_to_hash[..])
        }

        fn generate_relationship_key(
            entity: &T::EntityId,
            related_to: &T::EntityId,
            tag: Tag,
        ) -> [u8; 32] {
            let mut bytes_in_tag: Vec<u8> = tag.to_string().as_bytes().to_vec();
            let mut bytes_to_hash: Vec<u8> = entity.encode().as_slice().to_vec();
            let mut bytes_to_hash_relation: Vec<u8> = related_to.encode().as_slice().to_vec();
            bytes_to_hash.append(&mut bytes_to_hash_relation);
            bytes_to_hash.append(&mut bytes_in_tag);
            blake2_256(&bytes_to_hash[..])
        }
    }

    // implement the role Entity trait to satify the methods
    impl<T: Config> Role<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_role(entity: T::EntityId) -> Option<Entity<T::EntityId>> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            if <RoleStore<T>>::contains_key(&key) {
                return Some(Self::role_of(&key));
            }
            None
        }

        fn create_role(
            owner: &T::AccountId,
            entity: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // Check if role already exists
            if <RoleStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityAlreadyExist);
            }

            let new_role = Entity {
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

        fn update_existing_role(
            owner: &T::AccountId,
            entity: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // Get role
            let role = Self::get_role(entity);

            match role {
                Some(mut role) => {
                    role.name = (&name).to_vec();

                    <RoleStore<T>>::mutate(&key, |a| *a = role);
                    Ok(())
                }
                None => Err(EntityError::EntityDoesNotExist),
            }
        }

        fn delete_role(owner: &T::AccountId, entity: T::EntityId) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&entity, Tag::Role);

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            <RoleStore<T>>::remove(&key);

            // Remove the ownership of the role
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::remove((&owner, &key));

            Ok(())
        }
    }

    impl<T: Config> Permission<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_permission(permission_id: T::EntityId) -> Option<Entity<T::EntityId>> {
            // Generate key for integrity check
            let key = Self::generate_key(&permission_id, Tag::Permission);

            if <PermissionStore<T>>::contains_key(&key) {
                return Some(Self::role_of(&key));
            }
            None
        }

        fn create_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&permission_id, Tag::Permission);

            // Check if permission already exists
            if <PermissionStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityAlreadyExist);
            }

            let new_permission = Entity {
                id: permission_id,
                name: (&name).to_vec(),
            };

            <PermissionStore<T>>::insert(&key, new_permission);

            // Store the owner of the role for further validation
            // when modification is requested
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), permission_id.clone());

            Ok(())
        }
        fn update_existing_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&permission_id, Tag::Permission);

            // Check if permission exists
            if !<PermissionStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            let perm = Self::get_permission(permission_id);

            match perm {
                Some(mut p) => {
                    p.name = (&name).to_vec();

                    <PermissionStore<T>>::mutate(&key, |a| *a = p);
                    Ok(())
                }
                None => Err(EntityError::EntityDoesNotExist),
            }
        }
    }
}
