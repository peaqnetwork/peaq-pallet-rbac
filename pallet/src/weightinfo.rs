//! The trait definition for the weights of extrinsics.

use frame_support::weights::Weight;

pub trait WeightInfo {
    fn fetch_role() -> Weight;
    fn fetch_roles() -> Weight;
    fn add_role() -> Weight;
    fn update_role() -> Weight;
    fn disable_role() -> Weight;
    fn fetch_user_roles() -> Weight;
    fn assign_role_to_user() -> Weight;
    fn unassign_role_to_user() -> Weight;
    fn fetch_permission() -> Weight;
    fn fetch_permissions() -> Weight;
    fn add_permission() -> Weight;
    fn update_permission() -> Weight;
    fn disable_permission() -> Weight;
    fn fetch_role_permissions() -> Weight;
    fn assign_permission_to_role() -> Weight;
    fn unassign_permission_to_role() -> Weight;
    fn fetch_group() -> Weight;
    fn fetch_groups() -> Weight;
    fn add_group() -> Weight;
    fn update_group() -> Weight;
    fn disable_group() -> Weight;
    fn assign_role_to_group() -> Weight;
    fn unassign_role_to_group() -> Weight;
    fn fetch_group_roles() -> Weight;
    fn assign_user_to_group() -> Weight;
    fn unassign_user_to_group() -> Weight;
    fn fetch_user_groups() -> Weight;
    fn fetch_user_permissions() -> Weight;
    fn fetch_group_permissions() -> Weight;
}
