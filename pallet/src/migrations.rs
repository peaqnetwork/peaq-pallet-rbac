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

pub mod v1 {
	use super::*;

    #[storage_alias]
	type Role2GroupStore<T: Config> = StorageMap<Pallet<T>, Blake2_128Concat, Vec<Role2User<<T as pallet::Config>::EntityId>>, ValueQuery>;

    pub struct MigrateToV1x<T>(sp_std::marker::PhantomData<T>);

	impl<T: Config> MigrateToV1x<T> {
        pub fn on_runtime_upgrade() -> Weight {
            let onchain_version: StorageVersion = Pallet::<T>::on_chain_storage_version();
            let current_storage_version: StorageVersion = Pallet::<T>::current_storage_version();
    
            // expecting 0 < 1
            if onchain_version < current_storage_version {
                log::info!("Enter and do the migration, {:?} < {:?}", onchain_version, current_storage_version);
                // Role2UserStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
                // // Role2GroupStore::<T>::iter_values().map(|val| val.sort()).collect::<Vec<_>>();
                // Permission2RoleStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
                // User2GroupStore::<T>::iter_values().map(|mut val| val.sort()).collect::<Vec<_>>();
    
                // upgrade current_storage_version
                log::info!("Update current storage version af migration to {:?}", onchain_version);
                onchain_version.put::<Pallet<T>>();
            }
            T::DbWeight::get().reads_writes(0, 0)
        }
    }
}
