use std::sync::Arc;
use std::convert::From;

use codec::{Codec, Decode, Encode};
use sp_api::{ProvideRuntimeApi, ApiError};
use sp_blockchain::HeaderBackend;
// use peaq_pallet_did::structs::Attribute;
// pub use peaq_pallet_did_runtime_api::PeaqDIDApi as PeaqDIDRuntimeApi;
use peaq_pallet_rbac::structs::{Entity, Role2User, Role2Group, User2Group, Permission2Role};
pub use peaq_pallet_rbac_runtime_api::PeaqRBACRuntimeApi;
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
pub struct RpcEntity<EntityId> {
    pub id: EntityId,
    pub name: Bytes,
    pub enabled: bool,
}

impl<EntityId> From<Entity::<EntityId>> for RpcEntity<EntityId> {
    fn from(item: Entity::<EntityId>) -> Self {
        RpcEntity {
            id: item.id,
            name: item.name.into(),
            enabled: item.enabled,
        }
    }
}

// impl<EntityId> From<Vec<Entity::<EntityId>>> for RpcEntity<EntityId> {
//     fn from(item: Vec<Entity::<EntityId>>) -> Vec<Self> {
//         RpcEntity {
//             id: item.id,
//             name: item.name.into(),
//             enabled: item.enabled,
//         }
//     }
// }


#[derive(
    Clone, Encode, Decode, Serialize, Deserialize
)]
pub struct RpcRole2User<EntityId> {
    pub role: EntityId,
    pub user: EntityId,
}

impl<EntityId> From<Role2User::<EntityId>> for RpcRole2User<EntityId> {
    fn from(item: Role2User::<EntityId>) -> Self {
        RpcRole2User {
            role: item.role,
            user: item.user,
        }
    }
}


#[derive(
    Clone, Encode, Decode, Serialize, Deserialize
)]
pub struct RpcRole2Group<EntityId> {
    pub role: EntityId,
    pub group: EntityId,
}

impl<EntityId> From<Role2Group::<EntityId>> for RpcRole2Group<EntityId> {
    fn from(item: Role2Group::<EntityId>) -> Self {
        RpcRole2Group {
            role: item.role,
            group: item.group,
        }
    }
}


#[derive(
    Clone, Encode, Decode, Serialize, Deserialize
)]
pub struct RpcUser2Group<EntityId> {
    pub user: EntityId,
    pub group: EntityId,
}

impl<EntityId> From<User2Group::<EntityId>> for RpcUser2Group<EntityId> {
    fn from(item: User2Group::<EntityId>) -> Self {
        RpcUser2Group {
            user: item.user,
            group: item.group,
        }
    }
}


#[derive(
    Clone, Encode, Decode, Serialize, Deserialize
)]
pub struct RpcPermission2Role<EntityId> {
    pub permission: EntityId,
    pub role: EntityId,
}

impl<EntityId> From<Permission2Role::<EntityId>> for RpcPermission2Role<EntityId> {
    fn from(item: Permission2Role::<EntityId>) -> Self {
        RpcPermission2Role {
            permission: item.permission,
            role: item.role,
        }
    }
}


#[rpc(client, server)]
pub trait PeaqRBACApi<BlockHash, AccountId, EntityId> {
	/// RPC method for extrinsic call fetchRole
	#[method(name = "peaqrbac_fetchRole")]
	fn fetch_role(
		&self, account: AccountId, entity: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchRoles
	#[method(name = "peaqrbac_fetchRoles")]
	fn fetch_roles(
		&self, owner: AccountId, at: Option<BlockHash>
	) -> RpcResult<Vec<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchUserRoles
	#[method(name = "peaqrbac_fetchUserRoles")]
	fn fetch_user_roles(
		&self, owner: AccountId, user_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcRole2User<EntityId>>>>;

	/// RPC method for extrinsic call fetchPermission
	#[method(name = "peaqrbac_fetchPermission")]
	fn fetch_permission(
		&self, owner: AccountId, permission_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchPermissions
	#[method(name = "peaqrbac_fetchPermissions")]
	fn fetch_permissions(
		&self, owner: AccountId, at: Option<BlockHash>
	) -> RpcResult<Vec<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchRolePermissions
	#[method(name = "peaqrbac_fetchRolePermissions")]
	fn fetch_role_permissions(
		&self, owner: AccountId, role_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcPermission2Role<EntityId>>>>;

	/// RPC method for extrinsic call fetchGroup
	#[method(name = "peaqrbac_fetchGroup")]
	fn fetch_group(
		&self, owner: AccountId, group_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchGroups
	#[method(name = "peaqrbac_fetchGroups")]
	fn fetch_groups(
		&self, owner: AccountId, at: Option<BlockHash>
	) -> RpcResult<Vec<RpcEntity<EntityId>>>;

	/// RPC method for extrinsic call fetchGroupRoles
	#[method(name = "peaqrbac_fetchGroupRoles")]
	fn fetch_group_roles(
		&self, owner: AccountId, group_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcRole2Group<EntityId>>>>;
	
	/// RPC method for extrinsic call fetchUserGroups
	#[method(name = "peaqrbac_fetchUserGroups")]
	fn fetch_user_groups(
		&self, owner: AccountId, user_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcUser2Group<EntityId>>>>;

	/// RPC method for extrinsic call fetchUserPermissions
	#[method(name = "peaqrbac_fetchUserPermissions")]
	fn fetch_user_permissions(
		&self, owner: AccountId, user_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcEntity<EntityId>>>>;
	
	/// RPC method for extrinsic call fetchGroupPermissions
	#[method(name = "peaqrbac_fetchGroupPermissions")]
	fn fetch_group_permissions(
		&self, owner: AccountId, group_id: EntityId, at: Option<BlockHash>
	) -> RpcResult<Option<Vec<RpcEntity<EntityId>>>>;
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


// This macro simplifies copy&paste-work
// macro_rules! operate_with_api {
//     ($method:tt, $convert:tt) => {
//         let api = self.client.runtime_api();
// 		let at = BlockId::hash(at.unwrap_or(
// 			// If the block hash is not supplied assume the best block.
// 			self.client.info().best_hash,
// 		));
//         api.$method.map(|o| {
//             o.map($convert)
//         }).map_err(|e| {
// 			JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
// 				Error::RuntimeError.into(),
// 				"Unable to get value.",
// 				Some(format!("{:?}", e)),
// 			)))
// 		})
//     };
// }


#[inline]
fn map_api_err(err: ApiError) -> JsonRpseeError {
	JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
		Error::RuntimeError.into(),
		"Unable to get value.",
		Some(format!("{:?}", err)),
	)))
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
		RpcResult<Option<RpcEntity<EntityId>>>
    {
   		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        // api.fetch_role(&at, account, entity).map(|o| {
        //     o.map(|item| RpcEntity::from(item))
        // }).map_err(|e| {
		// 	JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
		// 		Error::RuntimeError.into(),
		// 		"Unable to get value.",
		// 		Some(format!("{:?}", e)),
		// 	)))
		// })
		api.fetch_role(&at, account, entity).map(|o| {
            o.map(|item| RpcEntity::from(item))
        }).map_err(|e| map_api_err(e))
    }

	fn fetch_roles(&self,
			owner: AccountId,
			at: Option<<Block as BlockT>::Hash>) -> 
		RpcResult<Vec<RpcEntity<EntityId>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
		api.fetch_roles(&at, owner).map(|v| {
            v.into_iter().map(|item| RpcEntity::from(item)).collect()
			// Vec::<RpcEntity<EntityId>>::from(v)
        }).map_err(|e| map_api_err(e))
	}

	fn fetch_user_roles(&self,
			owner: AccountId,
			user_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) -> 
		RpcResult<Option<Vec<RpcRole2User<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_user_roles(&at, owner, user_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcRole2User::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}

	fn fetch_permission(&self,
			owner: AccountId,
			permission_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<RpcEntity<EntityId>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_permission(&at, owner, permission_id).map(|o| {
            o.map(|item| RpcEntity::from(item))
        }).map_err(|e| map_api_err(e))
	}

	fn fetch_permissions(&self,
			owner: AccountId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Vec<RpcEntity<EntityId>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_permissions(&at, owner).map(|o| {
            o.into_iter().map(|item| RpcEntity::from(item)).collect()
        }).map_err(|e| map_api_err(e))
	}

	fn fetch_role_permissions(&self,
			owner: AccountId,
			role_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<Vec<RpcPermission2Role<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_role_permissions(&at, owner, role_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcPermission2Role::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}

	fn fetch_group(&self,
			owner: AccountId,
			group_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<RpcEntity<EntityId>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_group(&at, owner, group_id).map(|o| {
            o.map(|item| RpcEntity::from(item))
        }).map_err(|e| map_api_err(e))
	}

	fn fetch_groups(&self,
			owner: AccountId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Vec<RpcEntity<EntityId>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_groups(&at, owner).map(|v| {
            v.into_iter().map(|item| RpcEntity::from(item)).collect()
        }).map_err(|e| map_api_err(e))
	}

	fn fetch_group_roles(&self,
			owner: AccountId,
			group_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<Vec<RpcRole2Group<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_group_roles(&at, owner, group_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcRole2Group::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}
	 
	fn fetch_user_groups(&self,
			owner: AccountId,
			user_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<Vec<RpcUser2Group<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_user_groups(&at, owner, user_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcUser2Group::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}

	fn fetch_user_permissions(&self,
			owner: AccountId,
			user_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<Vec<RpcEntity<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_user_permissions(&at, owner, user_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcEntity::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}
	
	fn fetch_group_permissions(&self,
			owner: AccountId,
			group_id: EntityId,
			at: Option<<Block as BlockT>::Hash>) ->
		RpcResult<Option<Vec<RpcEntity<EntityId>>>>
	{
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or(
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash,
		));
        api.fetch_group_permissions(&at, owner, group_id).map(|o| o.map(|v| {
            v.into_iter().map(|item| RpcEntity::from(item)).collect()
        })).map_err(|e| map_api_err(e))
	}
}
