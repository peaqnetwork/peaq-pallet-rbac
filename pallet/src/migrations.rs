use super::*;

use frame_support::{
    dispatch::GetStorageVersion, pallet_prelude::StorageVersion, traits::Get, weights::Weight,
};
use sp_std::vec::Vec;
use structs::*;

pub(crate) fn on_runtime_upgrade<T: Config>() -> Weight {
    migrations::MigrateToV1x::<T>::on_runtime_upgrade()
}

pub mod migrations {

    use super::*;

    // This migration sort all values in some StorageMaps allowing them to be binary searchable
    // As there was no storage version set before, we set it now to 0
    pub struct MigrateToV1x<T>(sp_std::marker::PhantomData<T>);

    impl<T: Config> MigrateToV1x<T> {
        pub fn on_runtime_upgrade() -> Weight {
            let target_storage_version: StorageVersion = Pallet::<T>::current_storage_version();
            let on_chain_storage_version: StorageVersion = Pallet::<T>::on_chain_storage_version();

            if on_chain_storage_version < target_storage_version {
                log::info!(
                    "Pallet RBAC: Migration from onchain version {:?} to current version {:?}",
                    on_chain_storage_version,
                    target_storage_version,
                );

                // TODO repetitive translation logic with different types, reduce this with a macro
                // translate all vec to sorted vec
                Role2UserStore::<T>::translate_values::<Vec<Role2User<T::EntityId>>, _>(
                    |val: Vec<Role2User<T::EntityId>>| {
                        let mut sorted_val = val.clone();
                        sorted_val.sort();
                        Some(sorted_val)
                    },
                );

                // translate all vec to sorted vec
                Role2GroupStore::<T>::translate_values::<Vec<Role2Group<T::EntityId>>, _>(
                    |val: Vec<Role2Group<T::EntityId>>| {
                        let mut sorted_val = val.clone();
                        sorted_val.sort();
                        Some(sorted_val)
                    },
                );

                // translate all vec to sorted vec
                User2GroupStore::<T>::translate_values::<Vec<User2Group<T::EntityId>>, _>(
                    |val: Vec<User2Group<T::EntityId>>| {
                        let mut sorted_val = val.clone();
                        sorted_val.sort();
                        Some(sorted_val)
                    },
                );

                // translate all vec to sorted vec
                Permission2RoleStore::<T>::translate_values::<Vec<Permission2Role<T::EntityId>>, _>(
                    |val: Vec<Permission2Role<T::EntityId>>| {
                        let mut sorted_val = val.clone();
                        sorted_val.sort();
                        Some(sorted_val)
                    },
                );

                // upgrade current_storage_version
                log::info!(
                    "Pallet RBAC: Setting storage version to {:?}",
                    target_storage_version
                );
                target_storage_version.put::<Pallet<T>>();
            }
            T::DbWeight::get().reads_writes(0, 0)
        }
    }
}
