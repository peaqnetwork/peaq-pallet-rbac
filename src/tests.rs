use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn add_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let role_id = *b"21676474666576474646673646376637";
        let origin = account_key(acct);
        let name = b"CAN_EDIT";

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
        let name = b"CAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDITCAN_EDIT";
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
        let name = b"CAN_EDIT";

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
fn remove_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"23676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_EDIT";

        assert_ok!(PeaqRBAC::add_role(
            Origin::signed(origin),
            role_id,
            name.to_vec(),
        ));

        // Test for removal of role not owned by origin
        assert_noop!(
            PeaqRBAC::remove_role(Origin::signed(origin2), role_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::remove_role(Origin::signed(origin), role_id,));

        // Test for removal of non-existing role
        assert_noop!(
            PeaqRBAC::remove_role(Origin::signed(origin), role_id),
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
        let name = b"CAN_EDIT";

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
        let name = b"CAN_EDIT";

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
fn remove_role_to_user_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let acct2 = "Iredia2";
        let role_id = *b"25676474666576474646673646376637";
        let user_id = *b"12676474666576474646673646376637";
        let origin = account_key(acct);
        let origin2 = account_key(acct2);
        let name = b"CAN_EDIT";

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
            PeaqRBAC::remove_role_to_user(Origin::signed(origin2), role_id, user_id),
            Error::<Test>::EntityAuthorizationFailed
        );

        assert_ok!(PeaqRBAC::remove_role_to_user(
            Origin::signed(origin),
            role_id,
            user_id
        ));

        // Test for removing non-existing role
        assert_noop!(
            PeaqRBAC::remove_role_to_user(Origin::signed(origin), role_id, user_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}

#[test]
fn has_role_test() {
    new_test_ext().execute_with(|| {
        let acct = "Iredia";
        let role_id = *b"26676474666576474646673646376637";
        let user_id = *b"14676474666576474646673646376637";
        let origin = account_key(acct);
        let name = b"CAN_EDIT";

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

        assert_ok!(PeaqRBAC::has_role(Origin::signed(origin), role_id, user_id));

        // Test for non-existing role to user relationship
        let role_id = *b"26676474666576474646673646376638";
        assert_noop!(
            PeaqRBAC::has_role(Origin::signed(origin), role_id, user_id),
            Error::<Test>::EntityDoesNotExist
        );
    });
}
