use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn add_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let role_id = *b"21676474666576474646673646376637";
        let origin = account_key(acct);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::add_role(Origin::signed(origin), role_id, name.to_vec(),),
            Error::<Test>::EntityAlreadyExist
        );

        // Test name more than 64 chars
        let name = b"ADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMINADMIN";
        assert_noop!(
            PeaqRBAC::add_role(Origin::signed(origin), role_id, name.to_vec(),),
            Error::<Test>::EntityNameExceedMax64
        );
    });
}

#[test]
fn update_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"22676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        // Test for updating role not owned by origin
        let name = b"CAN_UPDATE";
        assert_noop!(
            PeaqRBAC::update_role(Origin::signed(origin2), role_id, name.to_vec()),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::update_role(
            Origin::signed(origin),
            role_id,
            name.to_vec()
        ));

        // Test for removal of non-existing role
        let role_id = *b"22676474666576474646673646376638";
        assert_noop!(
            PeaqRBAC::update_role(Origin::signed(origin), role_id, name.to_vec()),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn disable_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"23676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        // Test for removal of role not owned by origin
        assert_noop!(
            PeaqRBAC::disable_role(Origin::signed(origin2), role_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::disable_role(Origin::signed(origin), role_id,));

        // Test for removal of non-existing role
        assert_noop!(
            PeaqRBAC::disable_role(Origin::signed(origin), role_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let role_id = *b"23676474666576474646673646376637";
        let origin = account_key(acct);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::fetch_role(Origin::signed(origin), role_id,));

        // Test for fetching non-existing role
        let role_id = *b"23676474666576474646673646376638";
        assert_noop!(
            PeaqRBAC::fetch_role(Origin::signed(origin), role_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn assign_role_to_user_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"24676474666576474646673646376637";
        let user_id = *b"11676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        // Test for assigning role not owned by origin
        assert_noop!(
            PeaqRBAC::assign_role_to_user(Origin::signed(origin2), role_id, user_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::assign_role_to_user(
            Origin::signed(origin),
            role_id,
            user_id
        ));

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::assign_role_to_user(Origin::signed(origin), role_id, user_id),
            Error::<Test>::EntityAlreadyExist
        );

        // Test for assigning non-existing role
        let role_id = *b"24676474666576474646673646376638";
        assert_noop!(
            PeaqRBAC::assign_role_to_user(Origin::signed(origin), role_id, user_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn unassign_role_to_user_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"25676474666576474646673646376637";
        let user_id = *b"12676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::assign_role_to_user(
            Origin::signed(origin),
            role_id,
            user_id
        ));

        // Test for removing role not owned by origin
        assert_noop!(
            PeaqRBAC::unassign_role_to_user(Origin::signed(origin2), role_id, user_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::unassign_role_to_user(
            Origin::signed(origin),
            role_id,
            user_id
        ));

        // Test for removing non-existing role
        assert_noop!(
            PeaqRBAC::unassign_role_to_user(Origin::signed(origin), role_id, user_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_user_roles_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let role_id = *b"26676474666576474646673646376637";
        let user_id = *b"14676474666576474646673646376637";
        let origin = account_key(acct);
        let name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::assign_role_to_user(
            Origin::signed(origin),
            role_id,
            user_id
        ));

        assert_ok!(PeaqRBAC::fetch_user_roles(Origin::signed(origin), user_id));

        // Test for non-existing role to user relationship
        let user_id = *b"15676474666576474646673646376637";
        assert_noop!(
            PeaqRBAC::fetch_user_roles(Origin::signed(origin), user_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn add_permission_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let permission_id = *b"41464667364637663721676474666576";
        let origin = account_key(acct);
        let name = b"CAN_DELETE";

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::add_permission(Origin::signed(origin), permission_id, name.to_vec(),),
            Error::<Test>::EntityAlreadyExist
        );

        // Test name more than 64 chars
        let name = b"CAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETECAN_DELETE";
        assert_noop!(
            PeaqRBAC::add_permission(Origin::signed(origin), permission_id, name.to_vec(),),
            Error::<Test>::EntityNameExceedMax64
        );
    });
}

#[test]
fn update_permission_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let permission_id = *b"42464667364637663721676474666576";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_DELETE";

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        // Test for updating permission not owned by origin
        let name = b"CAN_UPDATE";
        assert_noop!(
            PeaqRBAC::update_permission(Origin::signed(origin2), permission_id, name.to_vec()),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::update_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec()
        ));

        // Test for removal of non-existing permission
        let permission_id = *b"42464667364637663721676474666577";
        assert_noop!(
            PeaqRBAC::update_permission(Origin::signed(origin), permission_id, name.to_vec()),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn disable_permission_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let permission_id = *b"43464667364637663721676474666576";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_DELETE";

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        // Test for removal of permission not owned by origin
        assert_noop!(
            PeaqRBAC::disable_permission(Origin::signed(origin2), permission_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::disable_permission(
            Origin::signed(origin),
            permission_id,
        ));

        // Test for removal of non-existing permission
        assert_noop!(
            PeaqRBAC::disable_permission(Origin::signed(origin), permission_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_permission_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let permission_id = *b"44464667364637663721676474666576";
        let origin = account_key(acct);
        let name = b"CAN_DELETE";

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::fetch_permission(
            Origin::signed(origin),
            permission_id,
        ));

        // Test for fetching non-existing permission
        let permission_id = *b"44464667364637663721676474666577";
        assert_noop!(
            PeaqRBAC::fetch_permission(Origin::signed(origin), permission_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn assign_permission_to_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let permission_id = *b"43464667364637663721676474666576";
        let role_id = *b"13464667364637663721676474666576";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_DELETE";
        let role_name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            role_name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        // Test for assigning permission not owned by origin
        assert_noop!(
            PeaqRBAC::assign_permission_to_role(Origin::signed(origin2), permission_id, role_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::assign_permission_to_role(
            Origin::signed(origin),
            permission_id,
            role_id
        ));

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::assign_permission_to_role(Origin::signed(origin), permission_id, role_id),
            Error::<Test>::EntityAlreadyExist
        );

        // Test for assigning non-existing permission
        let permission_id = *b"45464667364637663721676474666576";
        assert_noop!(
            PeaqRBAC::assign_permission_to_role(Origin::signed(origin), permission_id, role_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn unassign_permission_to_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let permission_id = *b"44464667364637663721676474666576";
        let role_id = *b"14464667364637663721676474666576";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_DELETE";
        let role_name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            role_name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::assign_permission_to_role(
            Origin::signed(origin),
            permission_id,
            role_id
        ));

        // Test for removing permission not owned by origin
        assert_noop!(
            PeaqRBAC::unassign_permission_to_role(Origin::signed(origin2), permission_id, role_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::unassign_permission_to_role(
            Origin::signed(origin),
            permission_id,
            role_id,
        ));

        // Test for removing non-existing permission
        assert_noop!(
            PeaqRBAC::unassign_permission_to_role(Origin::signed(origin), permission_id, role_id,),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_role_permissions_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let permission_id = *b"45464667364637663721676474666576";
        let role_id = *b"15464667364637663721676474666576";
        let origin = account_key(acct);
        let name = b"CAN_DELETE";
        let role_name = b"ADMIN";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            role_name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::add_permission(
            Origin::signed(origin),
            permission_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::assign_permission_to_role(
            Origin::signed(origin),
            permission_id,
            role_id
        ));

        assert_ok!(PeaqRBAC::fetch_role_permissions(
            Origin::signed(origin),
            role_id
        ));

        // Test for non-existing permission to role relationship
        let role_id = *b"15464667364637663721676474666577";
        assert_noop!(
            PeaqRBAC::fetch_role_permissions(Origin::signed(origin), role_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn add_group_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let group_id = *b"11663776474646673646665421676476";
        let origin = account_key(acct);
        let name = b"Users";

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id,
            name.to_vec(),
        ));

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::add_group(Origin::signed(origin), group_id, name.to_vec(),),
            Error::<Test>::EntityAlreadyExist
        );

        // Test name more than 64 chars
        let name = b"UsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsersUsers";
        assert_noop!(
            PeaqRBAC::add_group(Origin::signed(origin), group_id, name.to_vec(),),
            Error::<Test>::EntityNameExceedMax64
        );
    });
}

#[test]
fn update_group_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let group_id = *b"12663776474646673646665421676476";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"Users";

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id,
            name.to_vec(),
        ));

        // Test for updating group not owned by origin
        let name = b"Admins";
        assert_noop!(
            PeaqRBAC::update_group(Origin::signed(origin2), group_id, name.to_vec()),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::update_group(
            Origin::signed(origin),
            group_id,
            name.to_vec()
        ));

        // Test for removal of non-existing group
        let group_id = *b"12663776474646673646665421676477";
        assert_noop!(
            PeaqRBAC::update_group(Origin::signed(origin), group_id, name.to_vec()),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn disable_group_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let group_id = *b"13663776474646673646665421676476";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"Users";

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id,
            name.to_vec(),
        ));

        // Test for removal of group not owned by origin
        assert_noop!(
            PeaqRBAC::disable_group(Origin::signed(origin2), group_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::disable_group(Origin::signed(origin), group_id,));

        // Test for removal of non-existing group
        assert_noop!(
            PeaqRBAC::disable_group(Origin::signed(origin), group_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_group_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let group_id = *b"14663776474646673646665421676476";
        let origin = account_key(acct);
        let name = b"Users";

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::fetch_group(Origin::signed(origin), group_id,));

        // Test for fetching non-existing group
        let group_id = *b"14663776474646673646665421676477";
        assert_noop!(
            PeaqRBAC::fetch_group(Origin::signed(origin), group_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn fetch_groups_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let group_id = *b"15663776474646673646665421676476";
        let group_id2 = *b"16663776474646673646665421676476";
        let origin = account_key(acct);
        let name = b"Users";

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::add_group(
            Origin::signed(origin),
            group_id2,
            name.to_vec(),
        ));

        assert_ok!(PeaqRBAC::fetch_groups(Origin::signed(origin),));
    });
}
