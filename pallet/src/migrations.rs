use super::*;

use crate::rbac::*;
use frame_support::{
    dispatch::GetStorageVersion,
    pallet_prelude::{StorageVersion, ValueQuery},
    storage_alias,
    traits::Get,
    weights::Weight,
    Blake2_128Concat,
};
use structs::Role2User;

pub(crate) fn on_runtime_upgrade<T: Config>() -> Weight {
    v1::MigrateToV1x::<T>::on_runtime_upgrade()
}

const CURRENT_STORAGE_VERSION: StorageVersion = StorageVersion::new(0);

pub mod v1 {
    use super::*;

    pub struct MigrateToV1x<T>(sp_std::marker::PhantomData<T>);

    impl<T: Config> MigrateToV1x<T> {
        pub fn on_runtime_upgrade() -> Weight {
            let current_storage_version: StorageVersion = Pallet::<T>::current_storage_version();

            if current_storage_version.eq(&CURRENT_STORAGE_VERSION) {
                log::info!(
                    "Enter and do the migration for version 0 {:?}",
                    current_storage_version
                );

                // translate all vec to sorted vec
                Role2UserStore::<T>::translate_values::<Vec<Role2User<T::EntityId>>, _>(
                    |val: Vec<Role2User<T::EntityId>>| {
                        let mut sorted_val = val.clone();
                        sorted_val.sort();
                        Some(sorted_val)
                    },
                );

                // upgrade current_storage_version
                log::info!(
                    "Update current storage version of migration to {:?}",
                    current_storage_version
                );
                current_storage_version.put::<Pallet<T>>();
            }
            T::DbWeight::get().reads_writes(0, 0)
        }
    }
}
