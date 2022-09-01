//! Benchmarking setup for rbac

use super::*;

#[allow(unused)]
use crate::Pallet as RBAC;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;

benchmarks! {
    add_role {
        let s in 0 .. 100;
        let caller: T::AccountId = whitelisted_caller();
    }: _(RawOrigin::Signed(caller), s)
    verify {
        assert_eq!(RoleStore::<T>::get(), Some(s));
    }
}

impl_benchmark_test_suite!(RBAC, crate::mock::new_test_ext(), crate::mock::Test);
