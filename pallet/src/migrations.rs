use super::*;

use frame_support::{
	dispatch::GetStorageVersion,
	pallet_prelude::{StorageVersion, ValueQuery},
	storage_alias,
	traits::Get,
	weights::Weight,
    Blake2_128Concat
};
use structs::Role2User;

pub(crate) fn on_runtime_upgrade<T: Config>() -> Weight {
	v1::MigrateToV1x::<T>::on_runtime_upgrade()
}

const CURRENT_STORAGE_VERSION: StorageVersion = StorageVersion::new(0);

pub mod v1 {
	use super::*;

    #[storage_alias]
	type Role2GroupStore<T: Config> = StorageMap<Pallet<T>, Blake2_128Concat, Vec<Role2User<<T as pallet::Config>::EntityId>>, ValueQuery>;

    pub struct MigrateToV1x<T>(sp_std::marker::PhantomData<T>);

	impl<T: Config> MigrateToV1x<T> {
        pub fn on_runtime_upgrade() -> Weight {
            let current_storage_version: StorageVersion = Pallet::<T>::current_storage_version();
    
            // expecting 0 < 1
            if current_storage_version.eq(&CURRENT_STORAGE_VERSION) {
                log::info!("Enter and do the migration for version 0 {:?}", current_storage_version);
                // Role2UserStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
                // // Role2GroupStore::<T>::iter_values().map(|val| val.sort()).collect::<Vec<_>>();
                // Permission2RoleStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
                // User2GroupStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
    
                // upgrade current_storage_version
                log::info!("Update current storage version of migration to {:?}", current_storage_version);
                current_storage_version.put::<Pallet<T>>();
            }
            T::DbWeight::get().reads_writes(0, 0)
        }
    }
}
