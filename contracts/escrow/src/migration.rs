use crate::ttl::{read_if_live, remove_transient, store_with_ttl, PENDING_MIGRATION_TTL_LEDGERS};
use crate::{
    Contract, ContractStatus, ContractV1, DataKey, Error, Escrow, EscrowError,
    CONTRACT_STORAGE_SCHEMA_VERSION,
};
use soroban_sdk::{contracttype, Address, Env, Symbol};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingClientMigration {
    pub current_client: Address,
    pub proposed_client: Address,
    pub requested_at_ledger: u32,
    pub expires_at_ledger: u32,
}

impl Escrow {
    pub(crate) fn pending_migration_key(contract_id: u32) -> DataKey {
        DataKey::PendingClientMigration(contract_id)
    }

    pub(crate) fn load_contract(env: &Env, contract_id: u32) -> Contract {
        let version = Self::contract_schema_version(env, contract_id);
        if version < CONTRACT_STORAGE_SCHEMA_VERSION {
            return Self::migrate_contract_storage(env, contract_id, version);
        }
        env.storage()
            .persistent()
            .get::<_, Contract>(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound))
    }

    /// Return the stored schema version for `contract_id`, defaulting to `1`
    /// (the legacy, unversioned [`ContractV1`] layout) when no version marker
    /// has ever been written for it.
    pub(crate) fn contract_schema_version(env: &Env, contract_id: u32) -> u32 {
        env.storage()
            .persistent()
            .get::<_, u32>(&DataKey::ContractSchemaVersion(contract_id))
            .unwrap_or(1)
    }

    /// Upgrade a contract's persisted storage from `from_version` to
    /// [`CONTRACT_STORAGE_SCHEMA_VERSION`], rewriting it in place and stamping
    /// the schema version marker so subsequent reads take the fast path in
    /// [`Self::load_contract`]. Idempotent: calling it again on an
    /// already-current record is a no-op that simply re-reads the value.
    ///
    /// # Panics
    /// Panics with `Error::ContractNotFound` if no record exists for
    /// `contract_id` under any known layout.
    pub(crate) fn migrate_contract_storage(
        env: &Env,
        contract_id: u32,
        from_version: u32,
    ) -> Contract {
        if from_version >= CONTRACT_STORAGE_SCHEMA_VERSION {
            return env
                .storage()
                .persistent()
                .get::<_, Contract>(&DataKey::Contract(contract_id))
                .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));
        }

        // Only one legacy layout exists today (v1 -> v2). Extend this match
        // with further arms as CONTRACT_STORAGE_SCHEMA_VERSION advances.
        let migrated = match from_version {
            1 => {
                let legacy = env
                    .storage()
                    .persistent()
                    .get::<_, ContractV1>(&DataKey::Contract(contract_id))
                    .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));
                Contract {
                    client: legacy.client,
                    freelancer: legacy.freelancer,
                    arbiter: legacy.arbiter,
                    status: legacy.status,
                    total_deposited: legacy.total_deposited,
                    funded_amount: legacy.funded_amount,
                    released_amount: legacy.released_amount,
                    refunded_amount: legacy.refunded_amount,
                    release_authorization: legacy.release_authorization,
                    reputation_issued: false,
                }
            }
            _ => env.panic_with_error(Error::ContractNotFound),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Contract(contract_id), &migrated);
        env.storage().persistent().set(
            &DataKey::ContractSchemaVersion(contract_id),
            &CONTRACT_STORAGE_SCHEMA_VERSION,
        );

        env.events().publish(
            (Symbol::new(env, "contract_storage_migrated"), contract_id),
            (from_version, CONTRACT_STORAGE_SCHEMA_VERSION),
        );

        migrated
    }

    pub(crate) fn require_migration_allowed(env: &Env, status: ContractStatus) {
        if matches!(
            status,
            ContractStatus::Completed
                | ContractStatus::Cancelled
                | ContractStatus::Refunded
                | ContractStatus::Disputed
        ) {
            env.panic_with_error(Error::InvalidStatusTransition);
        }
    }

    pub(crate) fn pending_migration_exists(env: &Env, contract_id: u32) -> bool {
        read_if_live::<_, PendingClientMigration>(env, &Self::pending_migration_key(contract_id))
            .is_some()
    }

    /// Propose a client migration for an existing contract.
    ///
    /// The current client must authorize the call. The proposed client address
    /// must not be the freelancer or the current client. The pending migration
    /// is stored in temporary storage with TTL.
    pub(crate) fn propose_client_migration_impl(
        env: &Env,
        contract_id: u32,
        current_client: Address,
        new_client: Address,
    ) -> bool {
        Self::require_not_paused(&env);
        current_client.require_auth();

        let contract = Self::load_contract(&env, contract_id);
        Self::require_not_finalized(&env, contract_id);
        if current_client != contract.client {
            env.panic_with_error(EscrowError::UnauthorizedRole);
        }
        if new_client == contract.client || new_client == contract.freelancer {
            env.panic_with_error(EscrowError::InvalidParticipant);
        }
        Self::require_migration_allowed(&env, contract.status);
        if Self::pending_migration_exists(&env, contract_id) {
            env.panic_with_error(EscrowError::InvalidState);
        }

        let requested_at = env.ledger().sequence();
        let expires_at = requested_at.saturating_add(PENDING_MIGRATION_TTL_LEDGERS);
        let pending = PendingClientMigration {
            current_client: current_client.clone(),
            proposed_client: new_client.clone(),
            requested_at_ledger: requested_at,
            expires_at_ledger: expires_at,
        };
        store_with_ttl(
            &env,
            &Self::pending_migration_key(contract_id),
            &pending,
            PENDING_MIGRATION_TTL_LEDGERS,
        );

        env.events().publish(
            (Symbol::new(&env, "client_migration_proposed"), contract_id),
            (current_client, new_client, requested_at),
        );
        true
    }

    /// Accept a live pending client migration and update the contract.
    pub(crate) fn accept_client_migration_impl(
        env: &Env,
        contract_id: u32,
        new_client: Address,
    ) -> bool {
        Self::require_not_paused(&env);
        new_client.require_auth();

        let mut contract = Self::load_contract(&env, contract_id);
        Self::require_not_finalized(&env, contract_id);
        Self::require_migration_allowed(&env, contract.status);

        let key = Self::pending_migration_key(contract_id);
        let pending: PendingClientMigration = read_if_live(&env, &key)
            .unwrap_or_else(|| env.panic_with_error(EscrowError::InvalidState));

        if pending.proposed_client != new_client {
            env.panic_with_error(EscrowError::UnauthorizedRole);
        }
        if pending.current_client != contract.client {
            env.panic_with_error(EscrowError::InvalidState);
        }

        let key = Escrow::pending_migration_key(contract_id);
        let pending: PendingClientMigration = read_if_live(&env, &key)
            .unwrap_or_else(|| env.panic_with_error(EscrowError::InvalidState));

        env.events().publish(
            (Symbol::new(&env, "client_migration_accepted"), contract_id),
            (pending.current_client, new_client, env.ledger().timestamp()),
        );
        true
    }

    /// Cancel a live pending client migration.
    ///
    /// The current client must authorize the call, be the contract's client, and a live pending migration must exist.
    /// The pending migration entry is removed and a `client_migration_cancelled` event is emitted.
    pub fn cancel_client_migration(env: Env, contract_id: u32, current_client: Address) -> bool {
        Self::require_not_paused(&env);
        current_client.require_auth();

        let contract = Self::load_contract(&env, contract_id);
        Self::require_not_finalized(&env, contract_id);
        if current_client != contract.client {
            env.panic_with_error(EscrowError::UnauthorizedRole);
        }

        let key = Self::pending_migration_key(contract_id);
        // Ensure a pending migration exists, otherwise panic with InvalidState
        let _: PendingClientMigration = read_if_live(&env, &key)
            .unwrap_or_else(|| env.panic_with_error(EscrowError::InvalidState));

        // Remove the pending migration entry
        remove_transient(&env, &key);

        // Emit cancellation event
        env.events().publish(
            (Symbol::new(&env, "client_migration_cancelled"), contract_id),
            (current_client, env.ledger().timestamp()),
        );
        true
    }
    /// Return true if a live pending client migration exists.
    pub(crate) fn has_pending_client_migration_impl(env: &Env, contract_id: u32) -> bool {
        Self::pending_migration_exists(env, contract_id)
    }

    /// Return the live pending client migration record.
    pub(crate) fn get_pending_client_migration_impl(
        env: &Env,
        contract_id: u32,
    ) -> PendingClientMigration {
        read_if_live(&env, &Self::pending_migration_key(contract_id))
            .unwrap_or_else(|| env.panic_with_error(EscrowError::InvalidState))
    }
}
