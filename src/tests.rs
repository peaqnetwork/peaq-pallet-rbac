use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn add_role_test() {
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

        // Test for duplicate entry
        assert_noop!(
            PeaqRBAC::add_role(Origin::signed(origin), role_id, name.to_vec(),),
            Error::<Test>::EntityAlreadyExist
        );
    });
}
