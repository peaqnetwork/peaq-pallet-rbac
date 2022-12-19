use std::sync::Arc;
use std::convert::From;

use codec::{Codec, Decode, Encode};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
// use peaq_pallet_did::structs::Attribute;
// pub use peaq_pallet_did_runtime_api::PeaqDIDApi as PeaqDIDRuntimeApi;
use peaq_pallet_rbac::structs::{Entity};
pub use peaq_pallet_rbac_runtime_api::PeaqRBACApi as PeaqRBACRuntimeApi;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use sp_core::Bytes;
use serde::{Deserialize, Serialize};
use jsonrpsee::{
	core::{async_trait, Error as JsonRpseeError, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorObject},
};


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
    pub name: Bytes,
    pub enabled: bool,
}

impl<EntityId> From<Entity::<EntityId>> for RPCEntity<EntityId> {
    fn from(item: Entity::<EntityId>) -> Self {
        RPCEntity {
            id: item.id,
            name: item.name.into(),
            enabled: item.enabled,
        }
    }
}


#[rpc(client, server)]
pub trait PeaqRBACApi<BlockHash, AccountId, EntityId> {
	#[method(name = "peaqrbac_fetchRole")]
	fn fetch_role(&self, account: AccountId, entity: EntityId, at: Option<BlockHash>) -> 
		RpcResult<Option<RPCEntity<EntityId>>>;
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

impl From<Error> for i32 {
	fn from(e: Error) -> i32 {
		match e {
			Error::RuntimeError => 1,
		}
	}
}


#[async_trait]
impl<Client, Block, AccountId, EntityId> PeaqRBACApiServer<<Block as BlockT>::Hash, AccountId, EntityId> for PeaqRBAC<Client, Block>
where
    Block: BlockT,
    Client: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: PeaqRBACRuntimeApi<Block, AccountId, EntityId>,
	AccountId: Codec,
	EntityId: Codec
{
	fn fetch_role(&self,
            account: AccountId, 
            entity: EntityId, 
            at: Option<<Block as BlockT>::Hash>) -> 
		RpcResult<Option<RPCEntity<EntityId>>>
    {
   		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_role(&at, account, entity).map(|o| {
            o.map(|item| RPCEntity::from(item))
        }).map_err(|e| {
			JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
				Error::RuntimeError.into(),
				"Unable to get value.",
				Some(format!("{:?}", e)),
			)))
		})
    }
}
