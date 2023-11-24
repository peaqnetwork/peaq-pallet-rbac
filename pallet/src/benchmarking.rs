//! Benchmarking setup for rbac

use super::*;

#[allow(unused)]
use crate::Pallet as RBAC;
use frame_benchmarking::v1::{account, benchmarks, impl_benchmark_test_suite};
use frame_system::{Pallet as System, RawOrigin};

/// Assert that the last event equals the provided one.
fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    System::<T>::assert_last_event(generic_event.into());
}

const CALLER_ACCOUNT_STR: &str = "Iredia1";
const GROUP_ID: [u8; 32] = *b"66736466618663776474645421676476";
const GROUP_ID2: [u8; 32] = *b"16663776474646673646665421676476";
const USER_ID: [u8; 32] = *b"12676474666576474646673646376637";
const ROLE_ID: [u8; 32] = *b"21676474666576474646673646376637";
const ROLE_ID2: [u8; 32] = *b"23676474666576474646466746376631";
const PERMISSION_ID: [u8; 32] = *b"41464667364637663721676474666576";
const PERMISSION_ID2: [u8; 32] = *b"44464667364637663721676474666570";
const ADMIN_STR: &[u8] = b"ADMIN";
const GROUP_STR: &[u8] = b"Users";
const PERM_STR: &[u8] = b"CAN_DELETE";

benchmarks! {
    where_clause { where
        T: Config<EntityId = [u8; 32]>
    }

    add_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), ADMIN_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAdded(
            caller.clone(),
            ROLE_ID.clone(),
            ADMIN_STR.to_vec()
        ).into());
    }

    update_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), ADMIN_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUpdated(
            caller.clone(),
            ROLE_ID.clone(),
            ADMIN_STR.to_vec()
        ).into());
    }

    disable_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleRemoved(
            caller.clone(),
            ROLE_ID.clone(),
        ).into());
    }

    fetch_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), ROLE_ID.clone())

    fetch_roles {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID2.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())

    assign_role_to_user {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), USER_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAssignedToUser(
            caller.clone(),
            ROLE_ID.clone(),
            USER_ID.clone(),
        ).into());
    }

    unassign_role_to_user {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_role_to_user(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), USER_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), USER_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUnassignedToUser(
            caller.clone(),
            ROLE_ID.clone(),
            USER_ID.clone(),
        ).into());
    }

    assign_role_to_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;

    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), GROUP_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAssignedToGroup(
            caller.clone(),
            ROLE_ID.clone(),
            GROUP_ID.clone(),
        ).into());
    }

    unassign_role_to_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), GROUP_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), ROLE_ID.clone(), GROUP_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUnassignedToGroup(
            caller.clone(),
            ROLE_ID.clone(),
            GROUP_ID.clone(),
        ).into());
    }

    fetch_user_roles {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_role_to_user(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), USER_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), USER_ID.clone())

    add_permission {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), PERMISSION_ID.clone(), PERM_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionAdded(
            caller.clone(),
            PERMISSION_ID.clone(),
            PERM_STR.to_vec(),
        ).into());
    }

    update_permission {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), PERM_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), PERMISSION_ID.clone(), PERM_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionUpdated(
            caller.clone(),
            PERMISSION_ID.clone(),
            PERM_STR.to_vec(),
        ).into());
    }

    disable_permission {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), PERM_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), PERMISSION_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionDisabled(
            caller.clone(),
            PERMISSION_ID.clone(),
        ).into());
    }

    fetch_permission {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), PERM_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), PERMISSION_ID.clone())

    fetch_permissions {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), PERM_STR.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID2.clone(), PERM_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())

    assign_permission_to_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ADMIN_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), PERMISSION_ID.clone(), ROLE_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionAssigned(
            caller.clone(),
            PERMISSION_ID.clone(),
            ROLE_ID.clone(),
        ).into());
    }

    unassign_permission_to_role {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ROLE_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), PERMISSION_ID.clone(), ROLE_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionUnassignedToRole(
            caller.clone(),
            PERMISSION_ID.clone(),
            ROLE_ID.clone(),
        ).into());
    }

    fetch_role_permissions {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ROLE_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), ROLE_ID.clone())

    add_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), GROUP_ID.clone(), GROUP_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::GroupAdded(
            caller.clone(),
            GROUP_ID.clone(),
            GROUP_STR.to_vec(),
        ).into());
    }

    update_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), GROUP_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), GROUP_ID.clone(), GROUP_STR.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::GroupUpdated(
            caller.clone(),
            GROUP_ID.clone(),
            GROUP_STR.to_vec(),
        ).into());
    }

    disable_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), GROUP_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), GROUP_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::GroupDisabled(
            caller.clone(),
            GROUP_ID.clone(),
        ).into());
    }

    fetch_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), GROUP_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), GROUP_ID.clone())

    fetch_groups {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), GROUP_STR.to_vec())?;
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), GROUP_ID2.clone(), GROUP_STR.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())

    assign_user_to_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), GROUP_STR.to_vec())?;

    }: _(RawOrigin::Signed(caller.clone()), USER_ID.clone(), GROUP_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::UserAssignedToGroup(
            caller.clone(),
            USER_ID.clone(),
            GROUP_ID.clone(),
        ).into());
    }

    unassign_user_to_group {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), USER_ID.clone(), GROUP_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), USER_ID.clone(), GROUP_ID.clone())
    verify {
        assert_last_event::<T>(Event::<T>::UserUnAssignedToGroup(
            caller.clone(),
            USER_ID.clone(),
            GROUP_ID.clone(),
        ).into());
    }

    fetch_user_groups {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), USER_ID.clone(), GROUP_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), USER_ID.clone())

    fetch_user_permissions {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_permission(RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), USER_ID.clone(), GROUP_ID.clone())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), GROUP_ID.clone())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ROLE_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), USER_ID.clone())

    fetch_group_permissions {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_permission(RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), GROUP_ID.clone())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), PERMISSION_ID.clone(), ROLE_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), GROUP_ID.clone())

    fetch_group_roles {
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), GROUP_ID.clone(), ADMIN_STR.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), ROLE_ID.clone(), GROUP_ID.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), GROUP_ID.clone())
}

impl_benchmark_test_suite!(RBAC, crate::mock::new_test_ext(), crate::mock::Test);
