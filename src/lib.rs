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
    use sp_std::{vec, vec::Vec};

    use crate::rbac::Group;
    use crate::structs::Role2Group;
    use crate::{
        rbac::{EntityError, Permission, Rbac, Role, Tag},
        structs::{Entity, Permission2Role, Role2User},
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
    #[pallet::getter(fn role_to_user_of)]
    pub type Role2UserStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Vec<Role2User<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permission_of)]
    pub type PermissionStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Entity<T::EntityId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permission_to_role_of)]
    pub type Permission2RoleStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Vec<Permission2Role<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn group_of)]
    pub type GroupStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Entity<T::EntityId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn role_to_group_of)]
    pub type Role2GroupStore<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], Vec<Role2Group<T::EntityId>>, ValueQuery>;

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
        FetchedUserRoles(Vec<Role2User<T::EntityId>>),

        /// Event emitted when a permission has been added. [who, permissionId, permissionName]
        PermissionAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a permission has been updated. [who, permissionId, permissionName]
        PermissionUpdated(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a permission has been removed. [who, permissionId]
        PermissionRemoved(T::AccountId, T::EntityId),
        /// Event emitted when a permission has been assigned to role. [who, permissionId, roleId]
        PermissionAssigned(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a permission has been removed from role. [who, permissionId, roleId]
        PermissionRemovedFromRole(T::AccountId, T::EntityId, T::EntityId),
        FetchedRolePermissions(Vec<Permission2Role<T::EntityId>>),
        PermissionFetched(Entity<T::EntityId>),

        /// Event emitted when a group has been added. [who, groupId, roleName]
        GroupAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a group has been updated. [who, groupId, roleName]
        GroupUpdated(T::AccountId, T::EntityId, Vec<u8>),
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
        pub fn fetch_user_roles(origin: OriginFor<T>, user_id: T::EntityId) -> DispatchResult {
            ensure_signed(origin)?;
            let role_to_user = Self::get_user_roles(user_id);

            match role_to_user {
                Some(r2u) => {
                    Self::deposit_event(Event::FetchedUserRoles(r2u));
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

        #[pallet::weight(1_000)]
        pub fn fetch_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let permission = Self::get_permission(permission_id);

            match permission {
                Some(p) => {
                    Self::deposit_event(Event::PermissionFetched(p));
                }
                None => return Err(Error::<T>::EntityDoesNotExist.into()),
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

        #[pallet::weight(1_000)]
        pub fn remove_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::delete_permission(&sender, permission_id) {
                Ok(()) => {
                    Self::deposit_event(Event::PermissionRemoved(sender, permission_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        #[pallet::weight(1_000)]
        pub fn fetch_role_permissions(
            origin: OriginFor<T>,
            role_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let permission_to_role = Self::get_role_permissions(role_id);

            match permission_to_role {
                Some(p2r) => {
                    Self::deposit_event(Event::FetchedRolePermissions(p2r));
                }
                None => return Err(Error::<T>::EntityDoesNotExist.into()),
            };

            Ok(())
        }

        /// assign a permission to role call
        #[pallet::weight(1_000)]
        pub fn assign_permission_to_role(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::create_permission_to_role(&sender, permission_id, role_id) {
                Ok(()) => {
                    Self::deposit_event(Event::PermissionAssigned(sender, permission_id, role_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// remove permission to role relationship call
        #[pallet::weight(1_000)]
        pub fn remove_permission_to_role(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::delete_permission_to_role(&sender, permission_id, role_id) {
                Ok(()) => {
                    Self::deposit_event(Event::PermissionRemovedFromRole(
                        sender,
                        permission_id,
                        role_id,
                    ));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// create group call
        #[pallet::weight(1_000)]
        pub fn add_group(
            origin: OriginFor<T>,
            group_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::create_group(&sender, group_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::GroupAdded(sender, group_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// update group call
        #[pallet::weight(1_000)]
        pub fn update_group(
            origin: OriginFor<T>,
            group_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            match Self::update_existing_group(&sender, group_id, &name) {
                Ok(()) => {
                    Self::deposit_event(Event::GroupUpdated(sender, group_id, name));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }

        /// assign a role to group call
        #[pallet::weight(1_000)]
        pub fn assign_role_to_group(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            match Self::create_role_to_group(&sender, role_id, group_id) {
                Ok(()) => {
                    Self::deposit_event(Event::RoleAssigned(sender, role_id, group_id));
                }
                Err(e) => return Error::<T>::dispatch_error(e),
            };

            Ok(())
        }
    }
    // implement the Rbac trait to satify the methods
    impl<T: Config> Rbac<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_user_roles(user_id: T::EntityId) -> Option<Vec<Role2User<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(&user_id, Tag::Role2User);

            if <Role2UserStore<T>>::contains_key(&key) {
                return Some(Self::role_to_user_of(&key));
            }
            None
        }
        fn get_role_permissions(role_id: T::EntityId) -> Option<Vec<Permission2Role<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(&role_id, Tag::Permission2Role);

            if <Permission2RoleStore<T>>::contains_key(&key) {
                return Some(Self::permission_to_role_of(&key));
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
            let role_2_user_key = Self::generate_key(&user_id, Tag::Role2User);

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

            let mut roles: Vec<Role2User<T::EntityId>> = vec![];

            let new_assign = Role2User {
                role: role_id,
                user: user_id,
            };

            // Check if role has already been assigned to user
            if <Role2UserStore<T>>::contains_key(&role_2_user_key) {
                let mut val = <Role2UserStore<T>>::get(&role_2_user_key);

                if val.contains(&new_assign) {
                    return Err(EntityError::EntityAlreadyExist);
                }

                roles.append(&mut val);
            }
            roles.push(new_assign);

            <Role2UserStore<T>>::insert(&role_2_user_key, roles);

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
            let role_2_user_key = Self::generate_key(&user_id, Tag::Role2User);

            // Check if role exists
            if !<Role2UserStore<T>>::contains_key(&role_2_user_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            let new_assign = Role2User {
                role: role_id,
                user: user_id,
            };

            let mut val = <Role2UserStore<T>>::get(&role_2_user_key);

            if !val.contains(&new_assign) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &role_2_user_key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return Err(EntityError::EntityDoesNotExist),
            };

            if val.len() < 1 {
                <Role2UserStore<T>>::remove(&role_2_user_key);

                // Remove the ownership of the role
                let key = (&owner, &role_2_user_key).using_encoded(blake2_256);
                <OwnerStore<T>>::remove((&owner, &key));
            }

            if !val.is_empty() {
                <Role2UserStore<T>>::mutate(&role_2_user_key, |a| *a = val);
            }

            Ok(())
        }

        fn create_role_to_group(
            owner: &T::AccountId,
            role_id: T::EntityId,
            group_id: T::EntityId,
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let role_key = Self::generate_key(&role_id, Tag::Role);
            let role_2_group_key = Self::generate_key(&group_id, Tag::Role2Group);

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

            let mut roles: Vec<Role2Group<T::EntityId>> = vec![];

            let new_assign = Role2Group {
                role: role_id,
                group: group_id,
            };

            // Check if role has already been assigned to group
            if <Role2GroupStore<T>>::contains_key(&role_2_group_key) {
                let mut val = <Role2GroupStore<T>>::get(&role_2_group_key);

                if val.contains(&new_assign) {
                    return Err(EntityError::EntityAlreadyExist);
                }

                roles.append(&mut val);
            }
            roles.push(new_assign);

            <Role2GroupStore<T>>::insert(&role_2_group_key, roles);

            // Store the owner of the role assignment for further validation
            // when modification is requested
            let key = (&owner, &role_2_group_key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), group_id.clone());

            Ok(())
        }

        fn create_permission_to_role(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let role_key = Self::generate_key(&role_id, Tag::Role);
            let permission_key = Self::generate_key(&permission_id, Tag::Permission);
            let permission_2_role_key = Self::generate_key(&role_id, Tag::Permission2Role);

            // Check if role exists
            if !<RoleStore<T>>::contains_key(&role_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // Check if permission exists
            if !<PermissionStore<T>>::contains_key(&permission_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check role ownership
            let is_owner = Self::is_owner(owner, &role_key);
            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // check permission ownership
            let is_owner = Self::is_owner(owner, &permission_key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            let mut permissions: Vec<Permission2Role<T::EntityId>> = vec![];

            let new_assign = Permission2Role {
                permission: permission_id,
                role: role_id,
            };

            // Check if permission has already been assigned to role
            if <Permission2RoleStore<T>>::contains_key(&permission_2_role_key) {
                let mut val = <Permission2RoleStore<T>>::get(&permission_2_role_key);

                if val.contains(&new_assign) {
                    return Err(EntityError::EntityAlreadyExist);
                }

                permissions.append(&mut val);
            }
            permissions.push(new_assign);

            <Permission2RoleStore<T>>::insert(&permission_2_role_key, permissions);

            // Store the owner of the role assignment for further validation
            // when modification is requested
            let key = (&owner, &permission_2_role_key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), role_id.clone());

            Ok(())
        }

        fn delete_permission_to_role(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let permission_2_role_key = Self::generate_key(&role_id, Tag::Permission2Role);

            // Check if permission exists
            if !<Permission2RoleStore<T>>::contains_key(&permission_2_role_key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            let new_assign = Permission2Role {
                permission: permission_id,
                role: role_id,
            };

            let mut val = <Permission2RoleStore<T>>::get(&permission_2_role_key);

            if !val.contains(&new_assign) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &permission_2_role_key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return Err(EntityError::EntityDoesNotExist),
            };

            if val.len() < 1 {
                <Permission2RoleStore<T>>::remove(&permission_2_role_key);

                // Remove the ownership of the permission
                let key = (&owner, &permission_2_role_key).using_encoded(blake2_256);
                <OwnerStore<T>>::remove((&owner, &key));
            }

            if !val.is_empty() {
                <Permission2RoleStore<T>>::mutate(&permission_2_role_key, |a| *a = val);
            }

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
                return Some(Self::permission_of(&key));
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

            // Store the owner of the permission for further validation
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

        fn delete_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
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

            <PermissionStore<T>>::remove(&key);

            // Remove the ownership of the permission
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::remove((&owner, &key));

            Ok(())
        }
    }

    impl<T: Config> Group<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_group(group_id: T::EntityId) -> Option<Entity<T::EntityId>> {
            // Generate key for integrity check
            let key = Self::generate_key(&group_id, Tag::Group);

            if <GroupStore<T>>::contains_key(&key) {
                return Some(Self::group_of(&key));
            }
            None
        }
        fn create_group(
            owner: &T::AccountId,
            group_id: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&group_id, Tag::Group);

            // Check if group already exists
            if <GroupStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityAlreadyExist);
            }

            let new_group = Entity {
                id: group_id,
                name: (&name).to_vec(),
            };

            <GroupStore<T>>::insert(&key, new_group);

            // Store the owner of the group for further validation
            // when modification is requested
            let key = (&owner, &key).using_encoded(blake2_256);
            <OwnerStore<T>>::insert((&owner, &key), group_id.clone());

            Ok(())
        }

        fn update_existing_group(
            owner: &T::AccountId,
            group_id: T::EntityId,
            name: &[u8],
        ) -> Result<(), EntityError> {
            // Generate key for integrity check
            let key = Self::generate_key(&group_id, Tag::Group);

            // Check if group exists
            if !<GroupStore<T>>::contains_key(&key) {
                return Err(EntityError::EntityDoesNotExist);
            }

            // check ownership
            let is_owner = Self::is_owner(owner, &key);

            match is_owner {
                Err(e) => return Err(e),
                _ => (),
            }

            // Get group
            let group = Self::get_group(group_id);

            match group {
                Some(mut g) => {
                    g.name = (&name).to_vec();

                    <GroupStore<T>>::mutate(&key, |a| *a = g);
                    Ok(())
                }
                None => Err(EntityError::EntityDoesNotExist),
            }
        }
    }
}
