use crate as peaq_rbac;
use frame_support::parameter_types;
use frame_system as system;
use sp_runtime::BuildStorage;

use sp_core::{sr25519, Pair, H256};
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};

type Block = frame_system::mocking::MockBlock<Test>;
pub(crate) type Balance = u128;
pub(crate) type EntityId = [u8; 32];
pub(crate) type AccountId = sr25519::Public;

pub(crate) const DEPOSIT_BASE: Balance = 100;
pub(crate) const DEPOSIT_PER_BYTE: Balance = 2;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        PeaqRBAC: peaq_rbac,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Nonce = u64;
    type Block = Block;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type RuntimeTask = ();
}

parameter_types! {
    pub const MaxLocks: u32 = 4;
    pub const MaxReserves: u32 = 4;
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    // type MaxHolds = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = 5;
    pub const BoundedDataLen: u32 = 256;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const StorageDepositBase: Balance = DEPOSIT_BASE;
    pub const StorageDepositPerByte: Balance = DEPOSIT_PER_BYTE;
    pub const StorageReserveIdentifier: [u8; 8] = [b'p', b'e', b'a', b'q', b'r', b'b', b'a', b'c'];
}
impl peaq_rbac::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type EntityId = EntityId;
    type BoundedDataLen = BoundedDataLen;
    type WeightInfo = peaq_rbac::weights::WeightInfo<Test>;
    type StorageDepositBase = StorageDepositBase;
    type StorageDepositPerByte = StorageDepositPerByte;
    type Currency = Balances;
    type ReserveIdentifier = StorageReserveIdentifier;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    // This will cause some initial issuance
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (account_key("Iredia"), 1400000000000000000000000000),
            (account_key("Iredia2"), 1400000000000000000000000000),
            (account_key("FakeOrigin"), 1400000000000000000000000000),
        ],
    }
    .assimilate_storage(&mut storage)
    .ok();

    let mut ext = sp_io::TestExternalities::from(storage);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

pub fn account_key(s: &str) -> sr25519::Public {
    sr25519::Pair::from_string(&format!("//{}", s), None)
        .expect("static values are valid; qed")
        .public()
}
