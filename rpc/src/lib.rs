use std::sync::Arc;
use std::convert::From;

use codec::{Decode, Encode};
use codec::Codec;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
// use peaq_pallet_did::structs::Attribute;
// pub use peaq_pallet_did_runtime_api::PeaqDIDApi as PeaqDIDRuntimeApi;
use peaq_pallet_rbac::structs::{Entity};
pub use peaq_pallet_rbac_runtime_api::PeaqRBACApi as PeaqRBACRuntimeApi;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
// use sp_core::Bytes;
use serde::{Deserialize, Serialize};


// #[derive(
// 	Clone, Encode, Decode, Serialize, Deserialize
// )]
// pub struct RPCAttribute<BlockNumber, Moment> {
// 	pub name: Bytes,
// 	pub value: Bytes,
// 	pub validity: BlockNumber,
// 	pub created: Moment,
// }

// impl<BlockNumber, Moment> From<Attribute::<BlockNumber, Moment>> for RPCAttribute<BlockNumber, Moment> {
//     fn from(item: Attribute::<BlockNumber, Moment>) -> Self {
//         RPCAttribute {
//             name: item.name.into(),
//             value: item.value.into(),
//             validity: item.validity,
//             created: item.created,
//         }
//     }
// }
// Note: use peaq_pallet_rbac::structs::{Entity};

#[derive(
	Clone, Encode, Decode, Serialize, Deserialize
)]
pub struct RPCEntity<EntityId> {
    pub id: EntityId,
    pub name: Vec<u8>,
    pub enabled: bool,
}

impl<EntityId> From<Entity::<EntityId>> for RPCEntity<EntityId> {
    fn from(item: Entity::<EntityId>) -> Self {
        RPCEntity {
            id: item.id,
            name: item.name,
            enabled: item.enabled,
        }
    }
}


#[rpc]
pub trait PeaqRBACApi<OriginFor, AccountId, EntityId, BlockHash> {
	#[rpc(name = "peaqrbac_fetchRole")]
	fn fetch_role(&self, owner: OriginFor, did_account: AccountId, entity: EntityId, at: Option<BlockHash>) -> 
        Result<Option<RPCEntity<EntityId>>>;
}

/// A struct that implements the [`PeaqRBACApi`].
pub struct PeaqRBAC<Client, Block> {
	client: Arc<Client>,
	_marker: std::marker::PhantomData<Block>,
}

impl<Client, Block> PeaqRBAC<Client, Block> {
	/// Create new `PeaqRBAC` with the given reference to the client.
	pub fn new(client: Arc<Client>) -> Self {
		PeaqRBAC {
			client,
			_marker: Default::default(),
		}
	}
}

pub enum Error {
	RuntimeError,
}

impl From<Error> for i64 {
	fn from(e: Error) -> i64 {
		match e {
			Error::RuntimeError => 1,
		}
	}
}


impl<Client, Block, OriginFor, AccountId, EntityId> PeaqRBACApi<OriginFor, AccountId, EntityId, <Block as BlockT>::Hash> for PeaqRBAC<Client, Block>
where
    Block: BlockT,
    Client: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: PeaqRBACRuntimeApi<Block, OriginFor, AccountId, EntityId>,
    OriginFor: Codec,
	AccountId: Codec,
	EntityId: Codec
{
	fn fetch_role(&self, 
            owner: OriginFor, 
            did_account: AccountId, 
            entity: EntityId, 
            at: Option<<Block as BlockT>::Hash>) -> 
        Result<Option<RPCEntity<EntityId>>>
    {
   		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.read(&at, owner, did_account, entity).map(|o| {
            o.map(|item| RPCEntity::from(item))
        }).map_err(|e| RpcError {
    		code: ErrorCode::ServerError(Error::RuntimeError.into()),
    		message: "Unable to get value.".into(),
    		data: Some(format!("{:?}", e).into()),
    	})
    }
}
