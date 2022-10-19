//! Benchmarking setup for rbac

use super::*;

#[allow(unused)]
use crate::Pallet as RBAC;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, account};
use frame_system::{Pallet as System, RawOrigin};

/// Assert that the last event equals the provided one.
fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
    System::<T>::assert_last_event(generic_event.into());
}

const CALLER_ACCOUNT_STR: &str = "Iredia1";

benchmarks! {
	where_clause { where
        T: Config<EntityId = [u8; 32]>
	}

    add_role {
        let role_id = *b"21676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAdded(
            caller.clone(),
            role_id.clone(),
            name.to_vec()
        ).into());
    }

    update_role {
        let role_id = *b"21676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        let name = b"ADMIN";
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUpdated(
            caller.clone(),
            role_id.clone(),
            name.to_vec()
        ).into());
    }

    disable_role {
        let role_id = *b"21676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleRemoved(
            caller.clone(),
            role_id.clone(),
        ).into());
    }

    fetch_role {
        let role_id = *b"21676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), role_id.clone())
    verify {
    }

    fetch_roles {
        let role_id = *b"23676474666576474646673646376637";
        let role_id2 = *b"23676474666576474646466746376631";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id2.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())
    verify {
    }

    assign_role_to_user {
        let role_id = *b"23676474666576474646673646376637";
        let user_id = *b"11676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), user_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAssignedToUser(
            caller.clone(),
            role_id.clone(),
            user_id.clone(),
        ).into());
    }

    unassign_role_to_user {
        let role_id = *b"23676474666576474646673646376637";
        let user_id = *b"11676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_role_to_user(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), user_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), user_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUnassignedToUser(
            caller.clone(),
            role_id.clone(),
            user_id.clone(),
        ).into());
    }

    assign_role_to_group {
        let role_id = *b"23676474666576474646673646376637";
        let group_id = *b"11676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;

    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), group_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleAssignedToGroup(
            caller.clone(),
            role_id.clone(),
            group_id.clone(),
        ).into());
    }

    unassign_role_to_group {
        let role_id = *b"23676474666576474646673646376637";
        let group_id = *b"11676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), group_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), role_id.clone(), group_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::RoleUnassignedToGroup(
            caller.clone(),
            role_id.clone(),
            group_id.clone(),
        ).into());
    }

    fetch_user_roles {
        let role_id = *b"23676474666576474646673646376637";
        let user_id = *b"11676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_role_to_user(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), user_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), user_id.clone())
    verify {
    }

    add_permission {
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"CAN_DELETE";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), permission_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionAdded(
            caller.clone(),
            permission_id.clone(),
            name.to_vec(),
        ).into());
    }

    update_permission {
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"CAN_DELETE";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), permission_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionUpdated(
            caller.clone(),
            permission_id.clone(),
            name.to_vec(),
        ).into());
    }

    disable_permission {
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"CAN_DELETE";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), permission_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionDisabled(
            caller.clone(),
            permission_id.clone(),
        ).into());
    }

    fetch_permission {
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"CAN_DELETE";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), permission_id.clone())
    verify {
    }

    fetch_permissions {
        let permission_id = *b"41464667364637663721676474666576";
        let permission_id2 = *b"44464667364637663721676474666570";
        let name = b"CAN_DELETE";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id2.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())
    verify {
    }

    assign_permission_to_role {
        let role_id = *b"23676474666576474646673646376637";
        let user_id = *b"11676474666576474646673646376637";
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), permission_id.clone(), role_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionAssigned(
            caller.clone(),
            permission_id.clone(),
            role_id.clone(),
        ).into());
    }

    unassign_permission_to_role {
        let role_id = *b"23676474666576474646673646376637";
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), role_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), permission_id.clone(), role_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::PermissionUnassignedToRole(
            caller.clone(),
            permission_id.clone(),
            role_id.clone(),
        ).into());
    }

    fetch_role_permissions {
        let role_id = *b"23676474666576474646673646376637";
        let permission_id = *b"41464667364637663721676474666576";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), role_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), role_id.clone())
    verify {
    }

    add_group {
        let group_id = *b"11663776474646673646665421676476";
        let name = b"Users";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
    }: _(RawOrigin::Signed(caller.clone()), group_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::GroupAdded(
            caller.clone(),
            group_id.clone(),
            name.to_vec(),
        ).into());
    }

    update_group {
        let group_id = *b"11663776474646673646665421676476";
        let name = b"Users";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), group_id.clone(), name.to_vec())
    verify {
        assert_last_event::<T>(Event::<T>::GroupUpdated(
            caller.clone(),
            group_id.clone(),
            name.to_vec(),
        ).into());
    }

    disable_group {
        let group_id = *b"11663776474646673646665421676476";
        let name = b"Users";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), group_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::GroupDisabled(
            caller.clone(),
            group_id.clone(),
        ).into());
    }

    fetch_group {
        let group_id = *b"11663776474646673646665421676476";
        let name = b"Users";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), group_id.clone())
    verify {
    }

    fetch_groups {
        let group_id = *b"15663776474646673646665421676476";
        let group_id2 = *b"16663776474646673646665421676476";
        let name = b"Users";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(
            RawOrigin::Signed(caller.clone()).into(), group_id2.clone(), name.to_vec())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone())
    verify {
    }

    assign_user_to_group {
        let group_id = *b"17663776474646673646665421676476";
        let user_id = *b"12676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;

    }: _(RawOrigin::Signed(caller.clone()), user_id.clone(), group_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::UserAssignedToGroup(
            caller.clone(),
            user_id.clone(),
            group_id.clone(),
        ).into());
    }

    unassign_user_to_group {
        let group_id = *b"17663776474646673646665421676476";
        let user_id = *b"12676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), user_id.clone(), group_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), user_id.clone(), group_id.clone())
    verify {
        assert_last_event::<T>(Event::<T>::UserUnAssignedToGroup(
            caller.clone(),
            user_id.clone(),
            group_id.clone(),
        ).into());
    }

    fetch_user_groups {
        let group_id = *b"18663776474646673646665421676476";
        let user_id = *b"13676474666576474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), user_id.clone(), group_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), user_id.clone())
    verify {
    }

    fetch_user_permissions {
        let group_id = *b"66736466618663776474645421676476";
        let role_id = *b"46454667364666186637764721676476";
        let permission_id = *b"76472167646454667364666186637476";
        let user_id = *b"65761367647466474646673646376637";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_user_to_group(RawOrigin::Signed(caller.clone()).into(), user_id.clone(), group_id.clone())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), group_id.clone())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), role_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), user_id.clone())
    verify {
    }

    fetch_group_permissions {
        let group_id = *b"66736466618663776474645421676476";
        let role_id = *b"46454667364666186637764721676476";
        let permission_id = *b"76472167646454667364666186637476";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_permission(RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), group_id.clone())?;
        RBAC::<T>::assign_permission_to_role(
            RawOrigin::Signed(caller.clone()).into(), permission_id.clone(), role_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), group_id.clone())
    verify {
    }

    fetch_group_roles {
        let group_id = *b"66736466618663776474645421676476";
        let role_id = *b"46454667364666186637764721676476";
        let name = b"ADMIN";
        let caller : T::AccountId = account(CALLER_ACCOUNT_STR, 0, 0);
        RBAC::<T>::add_role(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), name.to_vec())?;
        RBAC::<T>::add_group(RawOrigin::Signed(caller.clone()).into(), group_id.clone(), name.to_vec())?;
        RBAC::<T>::assign_role_to_group(RawOrigin::Signed(caller.clone()).into(), role_id.clone(), group_id.clone())?;
    }: _(RawOrigin::Signed(caller.clone()), caller.clone(), group_id.clone())
    verify {
    }

}

impl_benchmark_test_suite!(RBAC, crate::mock::new_test_ext(), crate::mock::Test);
