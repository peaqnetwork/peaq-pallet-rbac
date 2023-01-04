//! peaq RBAC pallet
//!
//! The RBAC pallet allows resolving and management for  role-base access control in a generic manner.

#![cfg_attr(not(feature = "std"), no_std)]
// Fix benchmarking failure
#![recursion_limit = "256"]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod error;
pub mod rbac;
pub mod structs;

pub mod weights;
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {

    use codec::{Encode, MaxEncodedLen};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    use sp_std::fmt::Debug;
    use sp_std::{vec, vec::Vec};

    use super::WeightInfo;
    use crate::{
        error::{
            RbacError,
            RbacErrorType::{
                AssignmentAlreadyExist, AssignmentDoesNotExist, EntityAlreadyExist,
                EntityAuthorizationFailed, EntityDisabled, EntityDoesNotExist, NameExceedMaxChar,
            },
            Result,
        },
        rbac::{Group, Permission, Rbac, RbacKeyType, Role, Tag},
        structs::{Entity, Permission2Role, Role2Group, Role2User, User2Group},
    };

    macro_rules! dpatch_dposit {
        ($res:expr, $event:expr) => {
            match $res {
                Ok(d) => {
                    Self::deposit_event($event(d));
                    Ok(())
                }
                Err(e) => Error::<T>::dispatch_error(e),
            }
        };
    }

    macro_rules! dpatch_dposit_par {
        ($res:expr, $event:expr) => {
            match $res {
                Ok(_d) => {
                    Self::deposit_event($event);
                    Ok(())
                }
                Err(e) => Error::<T>::dispatch_error(e),
            }
        };
    }

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
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    // The pallet's runtime storage items.
    // https://docs.substrate.io/main-docs/build/runtime-storage/
    #[pallet::storage]
    #[pallet::getter(fn role_of)]
    pub type RoleStore<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Entity<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn role_to_user_of)]
    pub type Role2UserStore<T: Config> =
        StorageMap<_, Blake2_128Concat, RbacKeyType, Vec<Role2User<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permission_of)]
    pub type PermissionStore<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Entity<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permission_to_role_of)]
    pub type Permission2RoleStore<T: Config> =
        StorageMap<_, Blake2_128Concat, RbacKeyType, Vec<Permission2Role<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn group_of)]
    pub type GroupStore<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Entity<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn role_to_group_of)]
    pub type Role2GroupStore<T: Config> =
        StorageMap<_, Blake2_128Concat, RbacKeyType, Vec<Role2Group<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn user_to_group_of)]
    pub type User2GroupStore<T: Config> =
        StorageMap<_, Blake2_128Concat, RbacKeyType, Vec<User2Group<T::EntityId>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn keys_lookup_of)]
    pub type KeysLookUpStore<T: Config> =
        StorageMap<_, Blake2_128Concat, RbacKeyType, Entity<T::EntityId>, ValueQuery>;

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
        AllRolesFetched(Vec<Entity<T::EntityId>>),
        /// Event emitted when a role has been assigned to user. [who, roleId, userId]
        RoleAssignedToUser(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a role has been unassigned to user. [who, roleId, userId]
        RoleUnassignedToUser(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a role has been assigned to group. [who, roleId, groupId]
        RoleAssignedToGroup(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a role has been unassigned from group. [who, roleId, groupId]
        RoleUnassignedToGroup(T::AccountId, T::EntityId, T::EntityId),
        FetchedGroupRoles(Vec<Role2Group<T::EntityId>>),
        FetchedUserRoles(Vec<Role2User<T::EntityId>>),
        FetchedUserGroups(Vec<User2Group<T::EntityId>>),
        FetchedUserPermissions(Vec<Entity<T::EntityId>>),
        FetchedGroupPermissions(Vec<Entity<T::EntityId>>),

        /// Event emitted when a permission has been added. [who, permissionId, permissionName]
        PermissionAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a permission has been updated. [who, permissionId, permissionName]
        PermissionUpdated(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a permission has been disabled. [who, permissionId]
        PermissionDisabled(T::AccountId, T::EntityId),
        /// Event emitted when a permission has been assigned to role. [who, permissionId, roleId]
        PermissionAssigned(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a permission has been unassigned to role. [who, permissionId, roleId]
        PermissionUnassignedToRole(T::AccountId, T::EntityId, T::EntityId),
        FetchedRolePermissions(Vec<Permission2Role<T::EntityId>>),
        PermissionFetched(Entity<T::EntityId>),
        AllPermissionsFetched(Vec<Entity<T::EntityId>>),

        GroupFetched(Entity<T::EntityId>),
        AllGroupsFetched(Vec<Entity<T::EntityId>>),
        /// Event emitted when a group has been added. [who, groupId, roleName]
        GroupAdded(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a group has been updated. [who, groupId, roleName]
        GroupUpdated(T::AccountId, T::EntityId, Vec<u8>),
        /// Event emitted when a group has been disabled. [who, groupId]
        GroupDisabled(T::AccountId, T::EntityId),
        /// Event emitted when a user to group relationship has been added. [who, userId, groupId]
        UserAssignedToGroup(T::AccountId, T::EntityId, T::EntityId),
        /// Event emitted when a user to group relationship has been removed. [who, userId, groupId]
        UserUnAssignedToGroup(T::AccountId, T::EntityId, T::EntityId),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        /// Name exceeds 64
        EntityNameExceedMax64,
        /// Returned if the Role already exists
        EntityAlreadyExist,
        /// Returned if the Role does not exists
        EntityDoesNotExist,
        /// Returned if the Entity is not enabled
        EntityDisabled,
        /// Failed to verify entity ownership
        EntityAuthorizationFailed,
        /// Failed to assign entity to entity (e.g. user to group, role to user)
        AssignmentAlreadyExist,
        /// Returned if assignment does not exist
        AssignmentDoesNotExist,
    }

    impl<T: Config> Error<T> {
        fn dispatch_error(err: RbacError) -> DispatchResult {
            match err.typ {
                NameExceedMaxChar => Err(Error::<T>::EntityNameExceedMax64.into()),
                EntityAlreadyExist => Err(Error::<T>::EntityAlreadyExist.into()),
                EntityDoesNotExist => Err(Error::<T>::EntityDoesNotExist.into()),
                EntityAuthorizationFailed => Err(Error::<T>::EntityAuthorizationFailed.into()),
                EntityDisabled => Err(Error::<T>::EntityDisabled.into()),
                AssignmentAlreadyExist => Err(Error::<T>::AssignmentAlreadyExist.into()),
                AssignmentDoesNotExist => Err(Error::<T>::AssignmentDoesNotExist.into()),
            }
        }
    }

    // Dispatchable functions allows users to interact with the pallet and invoke state changes.
    // These functions materialize as "extrinsics", which are often compared to transactions.
    // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::fetch_role())]
        pub fn fetch_role(
            origin: OriginFor<T>,
            owner: T::AccountId,
            entity: T::EntityId,
        ) -> DispatchResult {
            // Check that an extrinsic was signed and get the signer
            // This fn returns an error if the extrinsic is not signed
            // https://docs.substrate.io/v3/runtime/origins
            ensure_signed(origin)?;
            let role = Self::get_role(&owner, entity);

            dpatch_dposit!(role, Event::RoleFetched)
        }

        #[pallet::weight(T::WeightInfo::fetch_roles())]
        pub fn fetch_roles(origin: OriginFor<T>, owner: T::AccountId) -> DispatchResult {
            ensure_signed(origin)?;
            let roles = Self::get_roles(&owner);

            // Self::deposit_event(Event::AllRolesFetched(roles));
            dpatch_dposit!(roles, Event::AllRolesFetched)
        }

        /// create role call
        #[pallet::weight(T::WeightInfo::add_role())]
        pub fn add_role(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::create_role(&sender, role_id, &name),
                Event::RoleAdded(sender, role_id, name)
            )
        }

        /// update role call
        #[pallet::weight(T::WeightInfo::update_role())]
        pub fn update_role(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::update_existing_role(&sender, role_id, &name),
                Event::RoleUpdated(sender, role_id, name)
            )
        }

        #[pallet::weight(T::WeightInfo::disable_role())]
        pub fn disable_role(origin: OriginFor<T>, role_id: T::EntityId) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::disable_existing_role(&sender, role_id),
                Event::RoleRemoved(sender, role_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_user_roles())]
        pub fn fetch_user_roles(
            origin: OriginFor<T>,
            owner: T::AccountId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // let role_to_user = Self::get_user_roles(&owner, user_id);

            dpatch_dposit!(
                Self::get_user_roles(&owner, user_id),
                Event::FetchedUserRoles
            )
        }

        /// assign a role to user call
        #[pallet::weight(T::WeightInfo::assign_role_to_user())]
        pub fn assign_role_to_user(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::create_role_to_user(&sender, role_id, user_id),
                Event::RoleAssignedToUser(sender, role_id, user_id)
            )
        }

        /// unassign role to user relationship call
        #[pallet::weight(T::WeightInfo::unassign_role_to_user())]
        pub fn unassign_role_to_user(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::revoke_role_to_user(&sender, role_id, user_id),
                Event::RoleUnassignedToUser(sender, role_id, user_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_permission())]
        pub fn fetch_permission(
            origin: OriginFor<T>,
            owner: T::AccountId,
            permission_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // let permission = Self::get_permission(owner, permission_id);

            dpatch_dposit!(
                Self::get_permission(&owner, permission_id),
                Event::PermissionFetched
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_permissions())]
        pub fn fetch_permissions(origin: OriginFor<T>, owner: T::AccountId) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(Self::get_permissions(&owner), Event::AllPermissionsFetched)
        }

        /// create permission call
        #[pallet::weight(T::WeightInfo::add_permission())]
        pub fn add_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::create_permission(&sender, permission_id, &name),
                Event::PermissionAdded(sender, permission_id, name)
            )
        }

        /// update permission call
        #[pallet::weight(T::WeightInfo::update_permission())]
        pub fn update_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::update_existing_permission(&sender, permission_id, &name),
                Event::PermissionUpdated(sender, permission_id, name)
            )
        }

        #[pallet::weight(T::WeightInfo::disable_permission())]
        pub fn disable_permission(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::disable_existing_permission(&sender, permission_id),
                Event::PermissionDisabled(sender, permission_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_role_permissions())]
        pub fn fetch_role_permissions(
            origin: OriginFor<T>,
            owner: T::AccountId,
            role_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // let permission_to_role = Self::get_role_permissions(&owner, role_id);

            dpatch_dposit!(
                Self::get_role_permissions(&owner, role_id),
                Event::FetchedRolePermissions
            )
        }

        /// assign a permission to role call
        #[pallet::weight(T::WeightInfo::assign_permission_to_role())]
        pub fn assign_permission_to_role(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::create_permission_to_role(&sender, permission_id, role_id),
                Event::PermissionAssigned(sender, permission_id, role_id)
            )
        }

        /// unassign permission to role relationship call
        #[pallet::weight(T::WeightInfo::unassign_permission_to_role())]
        pub fn unassign_permission_to_role(
            origin: OriginFor<T>,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::revoke_permission_to_role(&sender, permission_id, role_id),
                Event::PermissionUnassignedToRole(sender, permission_id, role_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_group())]
        pub fn fetch_group(
            origin: OriginFor<T>,
            owner: T::AccountId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // let group = Self::get_group(&owner, group_id);

            dpatch_dposit!(Self::get_group(&owner, group_id), Event::GroupFetched)
        }

        #[pallet::weight(T::WeightInfo::fetch_groups())]
        pub fn fetch_groups(origin: OriginFor<T>, owner: T::AccountId) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(Self::get_groups(&owner), Event::AllGroupsFetched)
        }

        /// create group call
        #[pallet::weight(T::WeightInfo::add_group())]
        pub fn add_group(
            origin: OriginFor<T>,
            group_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::create_group(&sender, group_id, &name),
                Event::GroupAdded(sender, group_id, name)
            )
        }

        /// update group call
        #[pallet::weight(T::WeightInfo::update_group())]
        pub fn update_group(
            origin: OriginFor<T>,
            group_id: T::EntityId,
            name: Vec<u8>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // Verify that the name len is 64 max
            ensure!(name.len() <= 64, Error::<T>::EntityNameExceedMax64);

            dpatch_dposit_par!(
                Self::update_existing_group(&sender, group_id, &name),
                Event::GroupUpdated(sender, group_id, name)
            )
        }

        /// disable group call
        #[pallet::weight(T::WeightInfo::disable_group())]
        pub fn disable_group(origin: OriginFor<T>, group_id: T::EntityId) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::disable_existing_group(&sender, group_id),
                Event::GroupDisabled(sender, group_id)
            )
        }

        /// assign a role to group call
        #[pallet::weight(T::WeightInfo::assign_role_to_group())]
        pub fn assign_role_to_group(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::create_role_to_group(&sender, role_id, group_id),
                Event::RoleAssignedToGroup(sender, role_id, group_id)
            )
        }

        /// unassign role to group relationship call
        #[pallet::weight(T::WeightInfo::unassign_role_to_group())]
        pub fn unassign_role_to_group(
            origin: OriginFor<T>,
            role_id: T::EntityId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::revoke_role_to_group(&sender, role_id, group_id),
                Event::RoleUnassignedToGroup(sender, role_id, group_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_group_roles())]
        pub fn fetch_group_roles(
            origin: OriginFor<T>,
            owner: T::AccountId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(
                Self::get_group_roles(&owner, group_id),
                Event::FetchedGroupRoles
            )
        }

        /// assign a user to group call
        #[pallet::weight(T::WeightInfo::assign_user_to_group())]
        pub fn assign_user_to_group(
            origin: OriginFor<T>,
            user_id: T::EntityId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::create_user_to_group(&sender, user_id, group_id),
                Event::UserAssignedToGroup(sender, user_id, group_id)
            )
        }

        /// unassign a user to group call
        #[pallet::weight(T::WeightInfo::unassign_user_to_group())]
        pub fn unassign_user_to_group(
            origin: OriginFor<T>,
            user_id: T::EntityId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            dpatch_dposit_par!(
                Self::revoke_user_to_group(&sender, user_id, group_id),
                Event::UserUnAssignedToGroup(sender, user_id, group_id)
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_user_groups())]
        pub fn fetch_user_groups(
            origin: OriginFor<T>,
            owner: T::AccountId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(
                Self::get_user_groups(&owner, user_id),
                Event::FetchedUserGroups
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_user_permissions())]
        pub fn fetch_user_permissions(
            origin: OriginFor<T>,
            owner: T::AccountId,
            user_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(
                Self::get_user_permissions(&owner, user_id),
                Event::FetchedUserPermissions
            )
        }

        #[pallet::weight(T::WeightInfo::fetch_group_permissions())]
        pub fn fetch_group_permissions(
            origin: OriginFor<T>,
            owner: T::AccountId,
            group_id: T::EntityId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            dpatch_dposit!(
                Self::get_group_permissions(&owner, group_id),
                Event::FetchedGroupPermissions
            )
        }
    }

    // implement the Rbac trait to satify the methods
    impl<T: Config> Rbac<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_entity(
            owner: &T::AccountId,
            entity_id: &T::EntityId,
            tag: Tag,
        ) -> Result<Entity<T::EntityId>> {
            let key = Self::generate_key(owner, entity_id, tag);

            if !<KeysLookUpStore<T>>::contains_key(&key) {
                return RbacError::err(EntityDoesNotExist, entity_id);
            }

            let entity = <KeysLookUpStore<T>>::get(&key);

            if !entity.enabled {
                return RbacError::err(EntityDisabled, entity_id);
            }

            Ok(entity)
        }

        fn check_entity_get_key(
            owner: &T::AccountId,
            entity_id: &T::EntityId,
            tag: Tag,
        ) -> Result<RbacKeyType> {
            let key = Self::generate_key(owner, entity_id, tag);

            if !<KeysLookUpStore<T>>::contains_key(&key) {
                return RbacError::err(EntityDoesNotExist, entity_id);
            }

            let entity = <KeysLookUpStore<T>>::get(&key);

            if !entity.enabled {
                return RbacError::err(EntityDisabled, entity_id);
            }

            Ok(key)
        }

        fn get_user_roles(
            owner: &T::AccountId,
            user_id: T::EntityId,
        ) -> Result<Vec<Role2User<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &user_id, Tag::Role2User);

            if <Role2UserStore<T>>::contains_key(&key) {
                Ok(Self::role_to_user_of(&key))
            } else {
                RbacError::err(AssignmentDoesNotExist, &user_id)
            }
        }

        fn get_user_groups(
            owner: &T::AccountId,
            user_id: T::EntityId,
        ) -> Result<Vec<User2Group<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &user_id, Tag::User2Group);

            if <User2GroupStore<T>>::contains_key(&key) {
                Ok(Self::user_to_group_of(&key))
            } else {
                RbacError::err(AssignmentDoesNotExist, &user_id)
            }
        }

        fn get_group_roles(
            owner: &T::AccountId,
            group_id: T::EntityId,
        ) -> Result<Vec<Role2Group<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &group_id, Tag::Role2Group);

            if <Role2GroupStore<T>>::contains_key(&key) {
                Ok(Self::role_to_group_of(&key))
            } else {
                RbacError::err(AssignmentDoesNotExist, &group_id)
            }
        }

        fn get_role_permissions(
            owner: &T::AccountId,
            role_id: T::EntityId,
        ) -> Result<Vec<Permission2Role<T::EntityId>>> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &role_id, Tag::Permission2Role);

            if <Permission2RoleStore<T>>::contains_key(&key) {
                Ok(Self::permission_to_role_of(&key))
            } else {
                RbacError::err(AssignmentDoesNotExist, &role_id)
            }
        }

        fn get_user_permissions(
            owner: &T::AccountId,
            user_id: T::EntityId,
        ) -> Result<Vec<Entity<T::EntityId>>> {
            // Generate key for integrity check
            let role_2_user_key = Self::generate_key(owner, &user_id, Tag::Role2User);
            let user_2_group_key = Self::generate_key(owner, &user_id, Tag::User2Group);

            let mut permissions: Vec<Entity<T::EntityId>> = vec![];
            // use to avoid duplicate transverval
            let mut processed_roles: Vec<T::EntityId> = vec![];

            if <Role2UserStore<T>>::contains_key(&role_2_user_key) {
                let val = <Role2UserStore<T>>::get(&role_2_user_key);

                let itr = val.iter();

                for r2u in itr {
                    // use to avoid duplicate transversal
                    processed_roles.push(r2u.role);

                    let p2r_option = Self::get_role_permissions(&owner, r2u.role)?;

                    for p2r in p2r_option.iter() {
                        let perm_option = Self::get_permission(owner, p2r.permission)?;
                        permissions.push(perm_option);
                    }
                }
            }

            if <User2GroupStore<T>>::contains_key(&user_2_group_key) {
                let val = <User2GroupStore<T>>::get(&user_2_group_key);

                let itr = val.iter();

                for u2g in itr {
                    let key = Self::generate_key(owner, &u2g.group, Tag::Role2Group);

                    if <Role2GroupStore<T>>::contains_key(&key) {
                        let val = <Role2GroupStore<T>>::get(&key);

                        let r2g_itr = val.iter();

                        for r2g in r2g_itr {
                            // use to avoid duplicate transversal
                            if !processed_roles.contains(&r2g.role) {
                                let p2r_option = Self::get_role_permissions(&owner, r2g.role)?;

                                for p2r in p2r_option.iter() {
                                    let perm_option =
                                        Self::get_permission(owner, p2r.permission)?;
                                    permissions.push(perm_option);
                                }
                            }
                        }
                    }
                }
            }

            Ok(permissions)
        }

        fn get_group_permissions(
            owner: &T::AccountId,
            group_id: T::EntityId,
        ) -> Result<Vec<Entity<T::EntityId>>> {
            // Generate key for integrity check

            let mut permissions: Vec<Entity<T::EntityId>> = vec![];

            let key = Self::generate_key(owner, &group_id, Tag::Role2Group);

            if <Role2GroupStore<T>>::contains_key(&key) {
                let val = <Role2GroupStore<T>>::get(&key);

                let r2g_itr = val.iter();

                for r2g in r2g_itr {
                    let p2r_option = Self::get_role_permissions(&owner, r2g.role)?;

                    for p2r in p2r_option.iter() {
                        let perm_option = Self::get_permission(owner, p2r.permission)?;
                        permissions.push(perm_option);
                    }
                }
            }

            Ok(permissions)
        }

        fn create_role_to_user(
            owner: &T::AccountId,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let role_key = Self::generate_key(owner, &role_id, Tag::Role);
            let role_2_user_key = Self::generate_key(owner, &user_id, Tag::Role2User);

            // Check if role exists
            if !<KeysLookUpStore<T>>::contains_key(&role_key) {
                return RbacError::err(EntityDoesNotExist, &role_id);
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
                    return RbacError::err(AssignmentAlreadyExist, &user_id);
                }

                roles.append(&mut val);
            }
            roles.push(new_assign);

            <Role2UserStore<T>>::insert(&role_2_user_key, roles);

            Ok(())
        }

        fn revoke_role_to_user(
            owner: &T::AccountId,
            role_id: T::EntityId,
            user_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let role_2_user_key = Self::generate_key(owner, &user_id, Tag::Role2User);

            // Check if role exists
            if !<Role2UserStore<T>>::contains_key(&role_2_user_key) {
                return RbacError::err(AssignmentDoesNotExist, &user_id);
            }

            let new_assign = Role2User {
                role: role_id,
                user: user_id,
            };

            let mut val = <Role2UserStore<T>>::get(&role_2_user_key);

            if !val.contains(&new_assign) {
                return RbacError::err(AssignmentDoesNotExist, &user_id);
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return RbacError::err(AssignmentDoesNotExist, &user_id),
            };

            if val.len() < 1 {
                <Role2UserStore<T>>::remove(&role_2_user_key);
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
        ) -> Result<()> {
            // Generate key for integrity check
            let group_key = Self::generate_key(owner, &group_id, Tag::Group);
            let role_key = Self::generate_key(owner, &role_id, Tag::Role);
            let role_2_group_key = Self::generate_key(owner, &group_id, Tag::Role2Group);

            // Check if role exists
            if !<KeysLookUpStore<T>>::contains_key(&role_key) {
                return RbacError::err(EntityDoesNotExist, &role_id);
            }

            // Check if group exists
            if !<KeysLookUpStore<T>>::contains_key(&group_key) {
                return RbacError::err(EntityDoesNotExist, &group_id);
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
                    return RbacError::err(AssignmentAlreadyExist, &group_id);
                }

                roles.append(&mut val);
            }
            roles.push(new_assign);

            <Role2GroupStore<T>>::insert(&role_2_group_key, roles);

            Ok(())
        }

        fn revoke_role_to_group(
            owner: &T::AccountId,
            role_id: T::EntityId,
            group_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let role_2_group_key = Self::generate_key(owner, &group_id, Tag::Role2Group);

            // Check if role exists
            if !<Role2GroupStore<T>>::contains_key(&role_2_group_key) {
                return RbacError::err(AssignmentDoesNotExist, &group_id);
            }

            let new_assign = Role2Group {
                role: role_id,
                group: group_id,
            };

            let mut val = <Role2GroupStore<T>>::get(&role_2_group_key);

            if !val.contains(&new_assign) {
                return RbacError::err(AssignmentDoesNotExist, &group_id);
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return RbacError::err(AssignmentDoesNotExist, &group_id),
            };

            if val.len() < 1 {
                <Role2GroupStore<T>>::remove(&role_2_group_key);
            }

            if !val.is_empty() {
                <Role2GroupStore<T>>::mutate(&role_2_group_key, |a| *a = val);
            }

            Ok(())
        }

        fn create_user_to_group(
            owner: &T::AccountId,
            user_id: T::EntityId,
            group_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let group_key = Self::generate_key(owner, &group_id, Tag::Group);
            let user_2_group_key = Self::generate_key(owner, &user_id, Tag::User2Group);

            // Check if group exists
            if !<KeysLookUpStore<T>>::contains_key(&group_key) {
                return RbacError::err(EntityDoesNotExist, &group_id);
            }

            let mut groups: Vec<User2Group<T::EntityId>> = vec![];

            let new_assign = User2Group {
                user: user_id,
                group: group_id,
            };

            // Check if role has already been assigned to group
            if <User2GroupStore<T>>::contains_key(&user_2_group_key) {
                let mut val = <User2GroupStore<T>>::get(&user_2_group_key);

                if val.contains(&new_assign) {
                    return RbacError::err(AssignmentAlreadyExist, &group_id);
                }

                groups.append(&mut val);
            }
            groups.push(new_assign);

            <User2GroupStore<T>>::insert(&user_2_group_key, groups);

            Ok(())
        }

        fn revoke_user_to_group(
            owner: &T::AccountId,
            user_id: T::EntityId,
            group_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let user_2_group_key = Self::generate_key(owner, &user_id, Tag::User2Group);

            // Check if user exists
            if !<User2GroupStore<T>>::contains_key(&user_2_group_key) {
                return RbacError::err(AssignmentDoesNotExist, &group_id);
            }

            let new_assign = User2Group {
                user: user_id,
                group: group_id,
            };

            let mut val = <User2GroupStore<T>>::get(&user_2_group_key);

            if !val.contains(&new_assign) {
                return RbacError::err(AssignmentDoesNotExist, &group_id);
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return RbacError::err(AssignmentDoesNotExist, &group_id),
            };

            if val.len() < 1 {
                <User2GroupStore<T>>::remove(&user_2_group_key);
            }

            if !val.is_empty() {
                <User2GroupStore<T>>::mutate(&user_2_group_key, |a| *a = val);
            }

            Ok(())
        }

        fn create_permission_to_role(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let role_key = Self::generate_key(owner, &role_id, Tag::Role);
            let permission_key = Self::generate_key(owner, &permission_id, Tag::Permission);
            let permission_2_role_key = Self::generate_key(owner, &role_id, Tag::Permission2Role);

            // Check if role exists
            if !<KeysLookUpStore<T>>::contains_key(&role_key) {
                return RbacError::err(EntityDoesNotExist, &role_id);
            }

            // Check if permission exists
            if !<KeysLookUpStore<T>>::contains_key(&permission_key) {
                return RbacError::err(EntityDoesNotExist, &permission_id);
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
                    return RbacError::err(AssignmentAlreadyExist, &role_id);
                }

                permissions.append(&mut val);
            }
            permissions.push(new_assign);

            <Permission2RoleStore<T>>::insert(&permission_2_role_key, permissions);

            Ok(())
        }

        fn revoke_permission_to_role(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            role_id: T::EntityId,
        ) -> Result<()> {
            // Generate key for integrity check
            let permission_2_role_key = Self::generate_key(owner, &role_id, Tag::Permission2Role);

            // Check if permission exists
            if !<Permission2RoleStore<T>>::contains_key(&permission_2_role_key) {
                return RbacError::err(AssignmentDoesNotExist, &role_id);
            }

            let new_assign = Permission2Role {
                permission: permission_id,
                role: role_id,
            };

            let mut val = <Permission2RoleStore<T>>::get(&permission_2_role_key);

            if !val.contains(&new_assign) {
                return RbacError::err(AssignmentDoesNotExist, &role_id);
            }

            match val.binary_search(&new_assign) {
                Ok(i) => val.remove(i),
                Err(_) => return RbacError::err(AssignmentDoesNotExist, &role_id),
            };

            if val.len() < 1 {
                <Permission2RoleStore<T>>::remove(&permission_2_role_key);
            }

            if !val.is_empty() {
                <Permission2RoleStore<T>>::mutate(&permission_2_role_key, |a| *a = val);
            }

            Ok(())
        }

        fn generate_key(owner: &T::AccountId, entity: &T::EntityId, tag: Tag) -> RbacKeyType {
            let mut bytes_in_tag: Vec<u8> = tag.to_string().as_bytes().to_vec();
            let mut entity_bytes_to_hash: Vec<u8> = entity.encode().as_slice().to_vec();
            let mut owner_bytes_to_hash: Vec<u8> = owner.encode().as_slice().to_vec();
            owner_bytes_to_hash.append(&mut entity_bytes_to_hash);
            owner_bytes_to_hash.append(&mut bytes_in_tag);
            blake2_256(&owner_bytes_to_hash[..])
        }
    }

    // implement the role Entity trait to satify the methods
    impl<T: Config> Role<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_role(owner: &T::AccountId, role_id: T::EntityId) -> Result<Entity<T::EntityId>> {
            Self::get_entity(&owner, &role_id, Tag::Role)
        }

        fn get_roles(owner: &T::AccountId) -> Result<Vec<Entity<T::EntityId>>> {
            Ok(<RoleStore<T>>::get(&owner))
        }

        fn create_role(owner: &T::AccountId, role_id: T::EntityId, name: &[u8]) -> Result<()> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &role_id, Tag::Role);

            // Check if role already exists
            if <KeysLookUpStore<T>>::contains_key(&key) {
                return RbacError::err(EntityAlreadyExist, &role_id);
            }

            let mut roles: Vec<Entity<T::EntityId>> = vec![];

            let new_role = Entity {
                id: role_id,
                name: (&name).to_vec(),
                enabled: true,
            };

            // Check if this account already had roles
            if <RoleStore<T>>::contains_key(&owner) {
                let mut val = <RoleStore<T>>::get(&owner);
                roles.append(&mut val);
            }
            roles.push(new_role.clone());

            <RoleStore<T>>::insert(&owner, roles);
            <KeysLookUpStore<T>>::insert(&key, new_role);

            Ok(())
        }

        fn update_existing_role(
            owner: &T::AccountId,
            role_id: T::EntityId,
            name: &[u8],
        ) -> Result<()> {
            // Check if role exists and it's enabled
            let key = Self::check_entity_get_key(owner, &role_id, Tag::Role)?;

            let mut val = <RoleStore<T>>::get(&owner);

            let iterator = val.iter_mut();

            for entity in iterator {
                if entity.id == role_id {
                    entity.name = (&name).to_vec();
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());

                    break;
                }
            }

            if !val.is_empty() {
                <RoleStore<T>>::mutate(&owner, |a| *a = val);
            }

            Ok(())
        }

        fn disable_existing_role(owner: &T::AccountId, role_id: T::EntityId) -> Result<()> {
            // Check if role exists and it's enabled and get key for integrity check
            let key = Self::check_entity_get_key(owner, &role_id, Tag::Role)?;

            let mut val = <RoleStore<T>>::get(&owner);

            let iterator = val.iter_mut();

            for entity in iterator {
                if entity.id == role_id {
                    entity.enabled = false;
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());
                    break;
                }
            }

            if !val.is_empty() {
                <RoleStore<T>>::mutate(&owner, |v| *v = val);
            }
            Ok(())
        }
    }

    impl<T: Config> Permission<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
        ) -> Result<Entity<T::EntityId>> {
            Self::get_entity(&owner, &permission_id, Tag::Permission)
        }

        fn get_permissions(owner: &T::AccountId) -> Result<Vec<Entity<T::EntityId>>> {
            Ok(<PermissionStore<T>>::get(&owner))
        }

        fn create_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            name: &[u8],
        ) -> Result<()> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &permission_id, Tag::Permission);

            // Check if permission already exists
            if <KeysLookUpStore<T>>::contains_key(&key) {
                return RbacError::err(EntityAlreadyExist, &permission_id);
            }

            let new_permission = Entity {
                id: permission_id,
                name: (&name).to_vec(),
                enabled: true,
            };

            let mut permissions: Vec<Entity<T::EntityId>> = vec![];

            // Check if this account already had permissions
            if <PermissionStore<T>>::contains_key(&owner) {
                let mut val = <PermissionStore<T>>::get(&owner);
                permissions.append(&mut val);
            }
            permissions.push(new_permission.clone());

            <PermissionStore<T>>::insert(&owner, permissions);
            <KeysLookUpStore<T>>::insert(&key, new_permission);

            Ok(())
        }

        fn update_existing_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
            name: &[u8],
        ) -> Result<()> {
            // Check if permission exists and it's enabled and get key for integrity check
            let key = Self::check_entity_get_key(owner, &permission_id, Tag::Permission)?;

            let mut val = <PermissionStore<T>>::get(&owner);

            let iterator = val.iter_mut();

            for entity in iterator {
                if entity.id == permission_id {
                    entity.name = (&name).to_vec();
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());
                    break;
                }
            }

            if !val.is_empty() {
                <PermissionStore<T>>::mutate(owner, |v| *v = val);
            }

            Ok(())
        }

        fn disable_existing_permission(
            owner: &T::AccountId,
            permission_id: T::EntityId,
        ) -> Result<()> {
            // Check if permission exists and it's enabled and get key for integrity check
            let key = Self::check_entity_get_key(owner, &permission_id, Tag::Permission)?;

            let mut val = <PermissionStore<T>>::get(&owner);

            let iterator = val.iter_mut();

            for entity in iterator {
                if entity.id == permission_id {
                    entity.enabled = false;
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());
                    break;
                }
            }

            if !val.is_empty() {
                <PermissionStore<T>>::mutate(owner, |v| *v = val);
            }

            Ok(())
        }
    }

    impl<T: Config> Group<T::AccountId, T::EntityId> for Pallet<T> {
        fn get_group(owner: &T::AccountId, group_id: T::EntityId) -> Result<Entity<T::EntityId>> {
            Self::get_entity(&owner, &group_id, Tag::Group)
        }

        fn get_groups(owner: &T::AccountId) -> Result<Vec<Entity<T::EntityId>>> {
            Ok(<GroupStore<T>>::get(owner))
        }

        fn create_group(owner: &T::AccountId, group_id: T::EntityId, name: &[u8]) -> Result<()> {
            // Generate key for integrity check
            let key = Self::generate_key(owner, &group_id, Tag::Group);

            // Check if group already exists
            if <KeysLookUpStore<T>>::contains_key(&key) {
                return RbacError::err(EntityAlreadyExist, &group_id);
            }

            let new_group = Entity {
                id: group_id,
                name: (&name).to_vec(),
                enabled: true,
            };

            let mut groups: Vec<Entity<T::EntityId>> = vec![];

            // Check if this account already had groups
            if <GroupStore<T>>::contains_key(owner) {
                let mut val = <GroupStore<T>>::get(owner);
                groups.append(&mut val);
            }
            groups.push(new_group.clone());

            <GroupStore<T>>::insert(owner, groups);
            <KeysLookUpStore<T>>::insert(&key, new_group);

            Ok(())
        }

        fn update_existing_group(
            owner: &T::AccountId,
            group_id: T::EntityId,
            name: &[u8],
        ) -> Result<()> {
            // Check if group exists and it's enabled and get key for integrity check
            let key = Self::check_entity_get_key(owner, &group_id, Tag::Group)?;

            let mut val = <GroupStore<T>>::get(owner);

            for entity in val.iter_mut() {
                if entity.id == group_id {
                    entity.name = (&name).to_vec();
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());
                    break;
                }
            }

            if !val.is_empty() {
                <GroupStore<T>>::mutate(owner, |v| *v = val);
            }
            Ok(())
        }

        fn disable_existing_group(owner: &T::AccountId, group_id: T::EntityId) -> Result<()> {
            // Check if group exists and it's enabled and get key for integrity check
            let key = Self::check_entity_get_key(owner, &group_id, Tag::Group)?;
            let mut val = <GroupStore<T>>::get(owner);

            for entity in val.iter_mut() {
                if entity.id == group_id {
                    entity.enabled = false;
                    <KeysLookUpStore<T>>::mutate(&key, |e| *e = entity.clone());
                    break;
                }
            }

            if !val.is_empty() {
                <GroupStore<T>>::mutate(owner, |v| *v = val);
            }
            Ok(())
        }
    }
}
