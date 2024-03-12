use super::*;

use frame_support::{
    dispatch::GetStorageVersion, pallet_prelude::StorageVersion, traits::Get, weights::Weight,
    BoundedVec,
};

use structs::*;

pub(crate) fn on_runtime_upgrade<T: Config>() -> Weight {
    MigrateToV1x::<T>::on_runtime_upgrade()
}

// This migration sort all values in some StorageMaps allowing them to be binary searchable
// As there was no storage version set before, we set it now to 0
pub struct MigrateToV1x<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> MigrateToV1x<T> {
    pub fn on_runtime_upgrade() -> Weight {
        let target_storage_version: StorageVersion = Pallet::<T>::current_storage_version();
        let on_chain_storage_version: StorageVersion = Pallet::<T>::on_chain_storage_version();

        let mut weight: u64 = 0;
        if on_chain_storage_version < target_storage_version {
            log::info!(
                "Pallet RBAC: Migration from onchain version {:?} to current version {:?}",
                on_chain_storage_version,
                target_storage_version,
            );

            // TODO repetitive translation logic with different types, reduce this with a macro
            // translate all vec to sorted vec
            Role2UserStore::<T>::translate_values::<
                BoundedVec<Role2User<T::EntityId>, T::BoundedDataLen>,
                _,
            >(
                |val: BoundedVec<Role2User<T::EntityId>, T::BoundedDataLen>| {
                    let mut sorted_val = val.clone();
                    sorted_val.sort();
                    weight += 1;
                    Some(sorted_val)
                },
            );

            // translate all vec to sorted vec
            Role2GroupStore::<T>::translate_values::<
                BoundedVec<Role2Group<T::EntityId>, T::BoundedDataLen>,
                _,
            >(
                |val: BoundedVec<Role2Group<T::EntityId>, T::BoundedDataLen>| {
                    let mut sorted_val = val.clone();
                    sorted_val.sort();
                    weight += 1;
                    Some(sorted_val)
                },
            );

            // translate all vec to sorted vec
            User2GroupStore::<T>::translate_values::<
                BoundedVec<User2Group<T::EntityId>, T::BoundedDataLen>,
                _,
            >(
                |val: BoundedVec<User2Group<T::EntityId>, T::BoundedDataLen>| {
                    let mut sorted_val = val.clone();
                    sorted_val.sort();
                    weight += 1;
                    Some(sorted_val)
                },
            );

            // translate all vec to sorted vec
            Permission2RoleStore::<T>::translate_values::<
                BoundedVec<Permission2Role<T::EntityId>, T::BoundedDataLen>,
                _,
            >(
                |val: BoundedVec<Permission2Role<T::EntityId>, T::BoundedDataLen>| {
                    let mut sorted_val = val.clone();
                    sorted_val.sort();
                    weight += 1;
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
        log::info!("Weight calculated: {:?}", weight);
        T::DbWeight::get().reads_writes(weight, weight)
    }
}
