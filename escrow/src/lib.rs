//! Delego Escrow Contract
//!
//! Holds funds in escrow until order fulfillment is confirmed.
//!
//! # Event topic schema
//!
//! Entity-scoped lifecycle events are published as `(escrow, <action>,
//! escrow_id)` so off-chain indexers and Soroban RPC subscriptions can filter
//! by escrow directly from the topics, without deserializing the event body
//! (issue #142). The id is also retained in the event data. The topic id type
//! matches the event's own id field: it is the `u64` `escrow_id` for every
//! action except `metadata` and `cancelled`, which carry the `BytesN<32>`
//! order id. Contract-wide events that have no single escrow to route by
//! (`upgraded`, `paused`, `feedist`, `pl_fund`, `pl_wdrw`, and the `admin`
//! transfer events) keep the two-topic `(escrow|admin, <action>)` form.

// Contract crates compile as no_std for release and wasm builds, but keep std
// enabled during testing so dev-dependencies and test assertions operate normally.
// This exact conditional form must be consistent across all workspace contract crates.
#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    InvokeError, Map, Symbol, Vec,
};

/// Lifecycle state of an escrow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    /// Escrow has been created but not yet funded.
    Created,
    /// Escrow has been funded by the buyer.
    Funded,
    /// Funds have been released to the seller.
    Released,
    /// Funds have been refunded to the buyer.
    Refunded,
    /// Escrow is disputed and awaiting resolution.
    Disputed,
    /// Escrow has been cancelled by an authorized party.
    Cancelled,
}

/// Terminal states an escrow can reach after it is no longer active.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowTerminalState {
    /// Funds were released to the seller.
    Released,
    /// Funds were refunded to the buyer.
    Refunded,
    /// Escrow was cancelled.
    Cancelled,
}

impl EscrowTerminalState {
    /// Returns the terminal state corresponding to the given status, if the status is terminal.
    pub fn from_status(status: &EscrowStatus) -> Option<Self> {
        match status {
            EscrowStatus::Released => Some(EscrowTerminalState::Released),
            EscrowStatus::Refunded => Some(EscrowTerminalState::Refunded),
            EscrowStatus::Cancelled => Some(EscrowTerminalState::Cancelled),
            _ => None,
        }
    }
}

/// Optional yield accrual configuration for an escrow (issue #331).
///
/// References an external lending contract that funds are notionally
/// deposited with while escrowed, and the annual rate at which yield
/// accrues for as long as the escrow remains held.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YieldConfig {
    /// Lending contract the escrowed funds notionally earn yield through.
    pub lending_contract: Address,
    /// Annual yield rate in basis points (e.g., 500 = 5% APR).
    pub apr_bps: u32,
}

/// Full on-chain record for a single escrow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowRecord {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Buyer's address.
    pub buyer: Address,
    /// Seller's address.
    pub seller: Address,
    /// Token contract address for the escrowed asset.
    pub token: Address,
    /// Total amount of tokens escrowed.
    pub amount: i128,
    /// Amount released to seller so far.
    pub released_amount: i128,
    /// Amount refunded to buyer so far.
    pub refunded_amount: i128,
    /// Current lifecycle state of the escrow.
    pub status: EscrowStatus,
    /// Off-chain order ID this escrow is associated with.
    pub order_id: BytesN<32>,
    /// Ledger timestamp when the escrow was created.
    pub created_at: u64,
    /// Ledger timestamp when the escrow was last updated.
    pub updated_at: u64,
    /// Ledger sequence at which the escrow can be refunded or disputed.
    pub timeout_ledger: u32,
}

/// Token-unit threshold above which escrow releases require finance approval.
pub const DUAL_CONTROL_THRESHOLD: i128 = 10_000;

/// Finance approval state for a high-value escrow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualControlConfig {
    /// Address authorized to provide the secondary approval.
    pub secondary_approver: Address,
    /// Whether the secondary approver has authorized release.
    pub is_secondary_approved: bool,
    /// Ledger timestamp of the secondary approval, or zero before approval.
    pub secondary_approved_at: u64,
}

/// Outcome of a partial release.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialReleaseResult {
    /// Amount released to the seller.
    pub released: i128,
    /// Amount still held in escrow.
    pub remaining: i128,
    /// Whether the escrow was fully released by this operation.
    pub fully_released: bool,
}

/// Outcome of a partial refund.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialRefundResult {
    /// Amount refunded to the buyer.
    pub refunded: i128,
    /// Amount still held in escrow.
    pub remaining: i128,
    /// Whether the escrow was fully refunded by this operation.
    pub fully_refunded: bool,
}

/// Legacy condition metadata retained for storage compatibility.
///
/// A boolean response from `oracle_contract` is no longer sufficient to
/// authorize release; use `SignedDeliveryProof` and
/// `verify_delivery_and_release` instead.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseCondition {
    pub condition_type: Symbol,
    pub oracle_contract: Address,
}

/// Delivery attestation signed by the configured Ed25519 delivery oracle.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDeliveryProof {
    pub escrow_id: u64,
    pub carrier_code: Symbol,
    pub tracking_hash: BytesN<32>,
    pub delivery_timestamp: u64,
    pub oracle_pubkey: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedDeliveryPayload {
    escrow_id: u64,
    carrier_code: Symbol,
    tracking_hash: BytesN<32>,
    delivery_timestamp: u64,
}

/// Emitted when a new escrow is created.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowCreatedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Buyer's address.
    pub buyer: Address,
    /// Seller's address.
    pub seller: Address,
    /// Token contract address for the escrowed asset.
    pub token: Address,
    /// Total amount of tokens escrowed.
    pub amount: i128,
    /// Off-chain order ID.
    pub order_id: BytesN<32>,
    /// Ledger sequence at which the escrow can be refunded or disputed.
    pub timeout_ledger: u32,
}

/// Emitted when escrow creation includes an off-chain order metadata hash.
///
/// `escrow_id` is the 32-byte order id so indexers can join contract events
/// to off-chain order records (same correlation key as `ReleaseEligibility`).
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowMetadataEvent {
    pub escrow_id: BytesN<32>,
    pub order_hash: BytesN<32>,
    pub schema: Symbol,
}

/// Emitted when an escrow is cancelled.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowCancelledEvent {
    /// The escrow ID (32-byte order ID).
    pub escrow_id: BytesN<32>,
    /// Address that cancelled the escrow.
    pub cancelled_by: Address,
    /// Symbolic reason for cancellation.
    pub reason: Symbol,
}

/// Emitted when funds are released to the seller.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowReleasedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Seller's address.
    pub seller: Address,
    /// Amount released to the seller.
    pub amount: i128,
    /// Address that triggered the release.
    pub released_by: Address,
}

/// Emitted alongside the release event when a fully-released escrow had a
/// `YieldConfig` set, reporting the yield accrued over its holding period
/// (issue #331).
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowYieldAccruedEvent {
    pub escrow_id: u64,
    pub seller: Address,
    pub yield_amount: i128,
    pub held_seconds: u64,
}

/// Emitted when funds are refunded to the buyer.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowRefundedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Buyer's address.
    pub buyer: Address,
    /// Amount refunded to the buyer.
    pub amount: i128,
    /// Amount remaining in escrow after this refund.
    pub remaining: i128,
    /// Address that triggered the refund.
    pub refunded_by: Address,
}

/// Emitted when a release condition is attached to an escrow.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ReleaseConditionSetEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Symbolic condition type forwarded to the oracle.
    pub condition_type: Symbol,
    /// Oracle contract that evaluates the condition.
    pub oracle_contract: Address,
}

/// Emitted when an escrow is disputed.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowDisputedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Address that initiated the dispute.
    pub disputed_by: Address,
}

/// Emitted when a dispute is resolved.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowResolvedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Whether the resolution releases funds to the seller.
    pub release_to_seller: bool,
    /// Address that resolved the dispute.
    pub resolved_by: Address,
}

/// Merkle proof for a delivery event committed by a published root.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleDeliveryProof {
    /// Daily Merkle root to verify against.
    pub root: BytesN<32>,
    /// SHA-256 hash of the escrow's `order_id`.
    pub leaf: BytesN<32>,
    /// Sibling hashes from the leaf to the root.
    pub proof: Vec<BytesN<32>>,
    /// Zero-based position of the leaf in the tree.
    pub index: u32,
}

/// Amounts and mediator recipient for a split dispute settlement.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeResolutionAward {
    /// Amount returned to the buyer.
    pub buyer_amount: i128,
    /// Amount paid to the seller.
    pub seller_amount: i128,
    /// Mediator's fee.
    pub mediator_fee: i128,
    /// Recipient of the mediator fee.
    pub mediator_address: Address,
}

/// Emitted after a disputed escrow is paid to the buyer, seller, and mediator.
#[contracttype]
#[derive(Clone, Debug)]
pub struct DisputeResolvedEvent {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Amount returned to the buyer.
    pub buyer_amount: i128,
    /// Amount paid to the seller.
    pub seller_amount: i128,
    /// Mediator's fee.
    pub mediator_fee: i128,
    /// Recipient of the mediator's fee.
    pub mediator_address: Address,
    /// Admin that resolved the dispute.
    pub resolved_by: Address,
}

/// Emitted on each arbiter vote during dispute resolution (#32).
///
/// Reports live tallies so indexers and UIs can track quorum progress
/// on-chain without replaying storage diffs.
#[contracttype]
#[derive(Clone, Debug)]
pub struct DisputeVotedEvent {
    pub escrow_id: u64,
    pub arbiter: Address,
    pub release_to_seller: bool,
    pub votes_for: u32,
    pub threshold: u32,
}

/// Emitted when escrowed funds are split among multiple recipients (#321).
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowSplitReleasedEvent {
    pub escrow_id: u64,
    pub recipient_count: u32,
    pub total_released: i128,
    pub fee_charged: i128,
    pub released_by: Address,
}

/// Emitted when an escrow's timeout ledger is extended (#323).
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowTimeoutExtendedEvent {
    pub escrow_id: u64,
    pub old_timeout_ledger: u32,
    pub new_timeout_ledger: u32,
    pub extended_by: Address,
}

/// Emitted when an admin transfer is proposed.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminProposedEvent {
    /// Current admin address.
    pub current_admin: Address,
    /// Proposed new admin address.
    pub new_admin: Address,
}

/// Emitted when a proposed admin accepts the transfer.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminAcceptedEvent {
    /// New admin address that accepted.
    pub new_admin: Address,
}

/// Emitted when a proposed admin transfer is cancelled.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminTransferCancelledEvent {
    /// Current admin address who cancelled the transfer.
    pub current_admin: Address,
}

/// Emitted when the contract's pause state changes.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowPauseChangedEvent {
    /// Whether the contract is now paused.
    pub paused: bool,
    /// Admin address that triggered the change.
    pub admin: Address,
    /// Ledger sequence number of the change.
    pub ledger: u32,
}

/// Pause state for the contract's create and deposit operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowPauseState {
    /// Whether new escrow creation is paused.
    pub create_paused: bool,
    /// Address that last updated the pause state.
    pub updated_by: Address,
    /// Ledger sequence of the last update.
    pub updated_at_ledger: u32,
    /// Ledger sequence at which the pause expires, if any.
    pub expires_at_ledger: Option<u32>,
}

/// Emitted when the contract is upgraded to new wasm code (issue #325).
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUpgradedEvent {
    pub admin: Address,
    pub previous_semver: Symbol,
    pub new_wasm_hash: BytesN<32>,
}

/// Pending multi-sig contract upgrade (issue #292).
///
/// Created by `propose_upgrade`, co-signed via `approve_upgrade`, and applied
/// by `upgrade` once `approvals` reaches the configured threshold and the
/// `UPGRADE_TIMELOCK_SECS` timelock measured from `proposed_at` has elapsed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    pub new_wasm_hash: BytesN<32>,
    pub proposed_at: u64,
    pub approvals: Vec<Address>,
    pub executed: bool,
}

/// Emitted when an admin proposes a contract upgrade (issue #292).
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUpgradeProposedEvent {
    pub proposer: Address,
    pub new_wasm_hash: BytesN<32>,
    pub proposed_at: u64,
    pub executable_at: u64,
    pub threshold: u32,
}

/// Emitted when an admin approves the pending upgrade proposal.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUpgradeApprovedEvent {
    pub approver: Address,
    pub new_wasm_hash: BytesN<32>,
    pub approval_count: u32,
    pub threshold: u32,
}

/// Emitted when an admin cancels the pending upgrade proposal.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUpgradeCancelledEvent {
    pub cancelled_by: Address,
    pub new_wasm_hash: BytesN<32>,
}

/// Emitted when the multi-treasury fee distribution is updated (issue #327).
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeDistributionSetEvent {
    pub admin: Address,
    pub treasury_count: u32,
    pub total_bps: u32,
}

/// Optional metadata hash stored on escrow creation for off-chain order verification.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowMetadata {
    /// Hash of off-chain order details (e.g., order JSON)
    pub order_hash: BytesN<32>,
    /// Schema identifier for the off-chain data (e.g., "order_v1")
    pub schema: Symbol,
}

/// Maps an escrow to its held token.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowTokenView {
    /// Unique identifier for the escrow.
    pub escrow_id: u64,
    /// Token contract address.
    pub token: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfig {
    /// Fee in basis points (e.g., 250 = 2.5%)
    pub fee_bps: u32,
    /// Address that receives the fee
    pub treasury: Address,
}

/// Complete escrow configuration including admin and fee parameters.
/// Used by `constructor` to atomically initialize the contract at deploy time
/// Used by `__constructor` to atomically initialize the contract at deploy time
/// without requiring post-deployment initialization calls that could be front-run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowConfig {
    pub admin: Address,
    pub fee_bps: u32,
    pub treasury: Address,
    pub min_amount: i128,
    pub max_amount: i128,
}

/// One treasury's share of the release fee, used by [`FeeConfig`]'s
/// multi-treasury successor configured via `set_fee_distribution`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryShare {
    /// Address that receives this share of the fee
    pub treasury: Address,
    /// Share in basis points (e.g., 250 = 2.5%)
    pub bps: u32,
}

/// Net seller payout plus the platform fee deducted for a release amount,
/// as computed by `compute_payout` (issue #27).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePayout {
    /// Amount the seller actually receives after the fee is deducted.
    pub seller_net: i128,
    /// Total fee charged across all treasuries.
    pub fee: i128,
    /// Primary treasury that receives the fee (from `FeeConfig`).
    pub treasury: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowAmountLimits {
    pub min_amount: i128,
    pub max_amount: i128,
}

/// One order's parameters for `batch_deposit` (issue #317). The buyer is
/// supplied once for the whole batch (see `batch_deposit`), not per order.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDepositParams {
    pub seller: Address,
    pub token: Address,
    pub amount: i128,
    pub order_id: BytesN<32>,
    pub timeout_ledgers: u32,
    pub order_hash: Option<BytesN<32>>,
    pub schema: Option<Symbol>,
}

/// One item for an atomic batch of funded escrows.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchEscrowItem {
    /// Seller receiving the funds after release.
    pub seller: Address,
    /// Whitelisted token to escrow.
    pub token: Address,
    /// Positive amount to escrow.
    pub amount: i128,
    /// Unique order identifier.
    pub order_id: BytesN<32>,
    /// Absolute ledger sequence when the escrow timeout expires.
    pub timeout_ledger: u32,
}

/// One escrow's release request for `batch_release` (issue #317).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReleaseParams {
    pub escrow_id: u64,
    pub release_amount: i128,
}

/// One escrow's refund request for `batch_refund` (issue #317).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRefundParams {
    pub escrow_id: u64,
    pub refund_amount: i128,
}

/// Shared liquidity reserve for a single token, used to instantly settle
/// funded escrows without waiting on the ordinary buyer/admin release flow
/// (issue #335).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiquidityPool {
    pub token: Address,
    pub balance: i128,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PoolFundedEvent {
    pub token: Address,
    pub funder: Address,
    pub amount: i128,
    pub new_balance: i128,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PoolWithdrawnEvent {
    pub token: Address,
    pub admin: Address,
    pub amount: i128,
    pub new_balance: i128,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PoolSettledEvent {
    pub escrow_id: u64,
    pub token: Address,
    pub seller: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumConfig {
    pub arbiters: soroban_sdk::Vec<Address>,
    pub threshold: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeVote {
    pub arbiter: Address,
    pub release_to_seller: bool,
}

/// A single arbiter's vote to extend an escrow's refund timeout, cast via
/// `extend_timeout_via_quorum` (issue #333).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutExtensionVote {
    pub arbiter: Address,
    pub extension_ledgers: u32,
    pub voted_at: u64,
}

/// Emitted once quorum is reached and `timeout_ledger` is extended.
#[contracttype]
#[derive(Clone, Debug)]
pub struct TimeoutExtendedEvent {
    pub escrow_id: u64,
    pub previous_timeout_ledger: u32,
    pub new_timeout_ledger: u32,
    pub extension_ledgers: u32,
}

/// Emitted when a keeper bumps TTL and receives a bounty.
#[contracttype]
#[derive(Clone, Debug)]
pub struct KeeperBountyPaidEvent {
    pub escrow_id: u64,
    pub keeper: Address,
    pub bounty_amount: i128,
    pub new_timeout_ledger: u32,
}

/// Emitted when a scheduled config change becomes effective.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ConfigChangeScheduledEvent {
    pub fee_bps: u32,
    pub treasury: Address,
    pub effective_ledger: u32,
    pub scheduled_at_ledger: u32,
    pub scheduled_by: Address,
}

/// Represents a scheduled fee configuration change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledFeeUpdate {
    pub fee_bps: u32,
    pub treasury: Address,
    pub effective_ledger: u32,
    pub scheduled_at_ledger: u32,
}

/// On-chain shipment proof record for timeout resolution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShipmentProof {
    /// Escrow ID this proof belongs to.
    pub escrow_id: u64,
    /// Carrier/shipping provider identifier.
    pub carrier: Symbol,
    /// Tracking number hash.
    pub tracking_hash: BytesN<32>,
    /// Timestamp when shipment was made.
    pub shipped_at: u64,
    /// Block timestamp when proof was recorded.
    pub recorded_at: u64,
}

/// Contract version information for deployment scripts and runtime compatibility checks.
///
/// # When to bump
/// - **Patch** (third digit): Bug fixes, internal refactors, gas optimizations — no
///   observable contract-behaviour change to callers.
/// - **Minor** (second digit): New read-only getters, new events, new optional
///   parameters — backward-compatible additions.
/// - **Major** (first digit): Breaking changes — removed functions, changed
///   function signatures, altered storage layout, modified event shapes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractVersion {
    pub name: Symbol,
    pub semver: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminView {
    pub admin: Address,
    pub pending_admin: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeVotesPrunedEvent {
    pub pruned_count: u32,
    pub pruned_by: Address,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Escrow(u64),
    /// Per-escrow finance approval configuration.
    DualControlConfig(u64),
    LastEscrowId,
    PendingAdmin,
    AdminList,
    FeeConfig,
    AmountLimits,
    QuorumConfig,
    DisputeVotes(u64),
    TimeoutExtensionVotes(u64),
    AllowedToken(Address),
    AllowedTokenAt(u32),
    AllowedTokenCount,
    PauseState,
    /// Order metadata hash half, persisted independently (issue #39).
    EscrowMetadataHash(u64),
    /// Order metadata schema half, persisted independently (issue #39).
    EscrowMetadataSchema(u64),
    LiquidityPool(Address),
    /// Set to `true` the first time the contract is upgraded via `upgrade`.
    MigrationFlag,
    /// Optional multi-treasury fee split configured via `set_fee_distribution`.
    FeeDistribution,
    /// Optional yield configuration for an escrow.
    EscrowYieldConfig(u64),
    /// Release condition for an escrow.
    ReleaseCondition(u64),
    /// Ed25519 public key authorized to sign delivery proofs.
    OraclePublicKey,
    /// Marketplace contract used to check whether escrow sellers may trade.
    MerchantRegistry,
    /// Authorized merchant categories for spend validation (MCC codes).
    AuthorizedCategories,
    /// Admin flag: when `true`, buyer-originated releases on the escrow must
    /// pass `get_release_eligibility` (issue #48).
    RequireReleaseCondition(u64),
    /// Append-only list of all escrow IDs, used for paginated enumeration (issue #49).
    EscrowIds,
    /// Number of escrow IDs in a buyer's index.
    BuyerEscrowCount(Address),
    /// Per-buyer escrow ID at a zero-based index.
    BuyerEscrowAt(Address, u32),
    /// Last ledger when bump_ttl_with_bounty was called (rate limiting).
    LastBumpLedger(u64),
    /// Scheduled fee update pending activation.
    ScheduledFeeUpdate,
    /// Shipment proof for an escrow (required for seller claim on timeout).
    ShipmentProof(u64),
    /// Current multi-sig upgrade proposal (issue #292).
    UpgradeProposal,
    /// M-of-N admin approvals required to execute an upgrade (issue #292).
    UpgradeThreshold,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
// Canonical ABI numbering for `EscrowError`.
//
// Error codes are part of the contract ABI. They are frozen for the 0.x
// deployment line; do not renumber, remove, or reuse existing codes. The
// declaration order below is not meaningful — the `#[repr(u32)]` values are.
//
// # Registry
//
// `First version` records the first contract version in which a code is
// known to be present. Legacy variants are marked `≤0.2.0` because they
// predate this audit; exact pre-0.2.0 introduction releases are not
// tracked.
//
// | Code | Variant | First version |
// |------|---------|---------------|
// | 1 | AlreadyInitialized | ≤0.2.0 |
// | 2 | NotFound | ≤0.2.0 |
// | 3 | Unauthorized | ≤0.2.0 |
// | 4 | AlreadyReleased | ≤0.2.0 |
// | 5 | AlreadyRefunded | ≤0.2.0 |
// | 6 | InvalidStatus | ≤0.2.0 |
// | 7 | TimeoutNotReached | ≤0.2.0 |
// | 8 | NotDisputed | ≤0.2.0 |
// | 9 | InvalidAmount | ≤0.2.0 |
// | 10 | TokenNotWhitelisted | ≤0.2.0 |
// | 11 | InsufficientEscrowBalance | ≤0.2.0 |
// | 12 | ZeroAmount | ≤0.2.0 |
// | 13 | NoPendingTransfer | ≤0.2.0 |
// | 14 | InvalidPendingAdmin | ≤0.2.0 |
// | 15 | AdminAlreadyExists | ≤0.2.0 |
// | 16 | InvalidFeeBps | ≤0.2.0 |
// | 17 | AmountBelowMin | ≤0.2.0 |
// | 18 | AmountAboveMax | ≤0.2.0 |
// | 19 | InvalidLimits | ≤0.2.0 |
// | 20 | NotAnArbiter | ≤0.2.0 |
// | 21 | AlreadyVoted | ≤0.2.0 |
// | 22 | InvalidQuorum | ≤0.2.0 |
// | 23 | QuorumNotReached | ≤0.2.0 |
// | 24 | QuorumConfigNotSet | ≤0.2.0 |
// | 25 | ConflictingQuorum | ≤0.2.0 |
// | 26 | CreationPaused | ≤0.2.0 |
// | 27 | AlreadyCancelled | ≤0.2.0 |
// | 28 | AlreadyFunded | ≤0.2.0 |
// | 29 | InvalidExtension | ≤0.2.0 |
// | 30 | PoolNotFound | ≤0.2.0 |
// | 31 | InsufficientPoolBalance | ≤0.2.0 |
// | 32 | InvalidAddress | ≤0.2.0 |
// | 33 | InvalidEscrowParticipants | ≤0.2.0 |
// | 36 | ReleaseConditionNotSet | ≤0.2.0 |
// | 37 | OracleCallFailed | ≤0.2.0 |
// | 38 | ConditionNotMet | ≤0.2.0 |
// | 39 | InvalidYieldConfig | ≤0.2.0 |
// | 40 | AmountLimitsNotSet | ≤0.2.0 |
// | 41 | FeeConfigNotSet | ≤0.2.0 |
// | 43 | MerchantNotTrading | New |
// | 44 | MerchantStatusCheckFailed | New |
// | 45 | SignedProofRequired | New |
// | 46 | InvalidSignedDeliveryProof | New |
// | 47 | OraclePublicKeyNotSet | New |
// | 201 | InvalidReleaseRecipient | ≤0.2.0 |
// | 400 | MetadataNotSet | next major |
// | 401 | InvalidMetadata | next major |
// | 402 | BumpRateLimitExceeded | next major |
// | 403 | BumpThresholdNotMet | next major |
// | 404 | ShipmentProofNotFound | next major |
// | 405 | FeeUpdateNotEffective | next major |
// | 406 | FeeNoticeWindowNotMet | next major |
// | 407 | UpgradeProposalExists | next major |
// | 408 | UpgradeProposalNotFound | next major |
// | 409 | UpgradeTimelockActive | next major |
// | 410 | UpgradeHashMismatch | next major |
// | 411+ | Reserved for new variants | next major |
//
// # Allocating new variants
//
// New variants MUST use codes in the reserved contiguous range starting at
// 400. Do not fill historical gaps or reuse codes from the registry above.
// | 400+ | Reserved for new variants | next major |
// # Cross-contract allocation
// The contract error enums (`EscrowError`, `PermissionError`,
// `ReputationError`, `DelegationError`, `MarketplaceError`) share a single
// numeric ABI space when errors surface over a bridge.  Each contract owns
// a disjoint range; the table below is the canonical allocation and is
// checked by `error_code_allocation_tests`.
// | Contract | Error enum | Allocated range |
// |----------|------------|-----------------|
// | escrow | `EscrowError` | 400..=999 |
// | permission | `PermissionError` | 1_000..=1_999 |
// | reputation | `ReputationError` | 2_000..=2_999 |
// | delegation | `DelegationError` | 3_000..=3_999 |
// | marketplace | `MarketplaceError` | 4_000..=4_999 |
// The 0.x codes in the registry above are frozen legacy codes; they predate
// this table. New `EscrowError` variants MUST use `400..=999` (or the 1.0
// renumbered range) and MUST NOT use another contract's range.
// New variants MUST use codes in the escrow allocation (`400..=999`) and
// MUST NOT use another contract's range. Do not fill historical gaps or
// reuse codes from the registry above.
//
// # Renumber plan
//
// The next `ContractVersion` major bump (1.0.0) is the planned breaking
// release for renumbering `EscrowError` contiguously from 1 to N, removing
// gaps and sorting declaration order by code. Until that release, the codes
// in the registry above are stable.
// release for renumbering `EscrowError` contiguously inside the escrow
// allocation range (`400..=999`), removing gaps and sorting declaration
// order by code. Until that release, the codes in the registry above are
// stable.
/// Canonical ABI error codes for the escrow contract; see the registry above.
pub enum EscrowError {
    /// Contract already initialized
    AlreadyInitialized = 1,
    /// Escrow record not found
    NotFound = 2,
    /// Caller is not authorized for this operation
    Unauthorized = 3,
    /// Escrow has already been released
    AlreadyReleased = 4,
    /// Escrow has already been refunded
    AlreadyRefunded = 5,
    /// Escrow is not in Funded status
    InvalidStatus = 6,
    /// Refund timeout has not been reached
    TimeoutNotReached = 7,
    /// Escrow is not in Disputed status
    NotDisputed = 8,
    /// Invalid amount (zero or negative)
    InvalidAmount = 9,
    /// Address is zero or otherwise invalid for this contract action
    InvalidAddress = 32,
    /// Buyer and seller must be distinct parties
    InvalidEscrowParticipants = 33,
    /// Token is not approved for escrow deposits
    TokenNotWhitelisted = 10,
    /// Release amount exceeds remaining escrow balance
    InsufficientEscrowBalance = 11,
    /// Release amount is zero
    ZeroAmount = 12,
    /// No pending admin transfer exists
    NoPendingTransfer = 13,
    /// Caller is not the pending admin
    InvalidPendingAdmin = 14,
    /// Admin already exists
    AdminAlreadyExists = 15,
    /// Fee BPS exceeds maximum (1000 bps = 10%)
    InvalidFeeBps = 16,
    /// Amount is below the minimum allowed
    AmountBelowMin = 17,
    /// Amount is above the maximum allowed
    AmountAboveMax = 18,
    /// Invalid limits (min <= 0 or max < min)
    InvalidLimits = 19,
    /// Not an authorized arbiter
    NotAnArbiter = 20,
    /// Arbiter has already voted
    AlreadyVoted = 21,
    /// Invalid quorum threshold
    InvalidQuorum = 22,
    /// Quorum not yet reached
    QuorumNotReached = 23,
    /// Quorum config not set
    QuorumConfigNotSet = 24,
    /// Conflicting quorum outcomes
    ConflictingQuorum = 25,
    /// Release recipient does not match the stored seller address
    InvalidReleaseRecipient = 201,
    /// New escrow creation is currently paused by admin
    CreationPaused = 26,
    /// Escrow has already been cancelled
    AlreadyCancelled = 27,
    /// Escrow has already been funded
    AlreadyFunded = 28,
    /// Extension length must be greater than zero
    InvalidExtension = 29,
    /// No liquidity pool exists for the given token
    PoolNotFound = 30,
    /// Liquidity pool balance is insufficient for the requested operation
    InsufficientPoolBalance = 31,
    /// Release condition has not been set for this escrow
    ReleaseConditionNotSet = 36,
    /// Oracle call failed or returned an unexpected result
    OracleCallFailed = 37,
    /// Oracle condition was not met
    ConditionNotMet = 38,
    /// Invalid yield configuration (e.g. APR exceeds maximum)
    InvalidYieldConfig = 39,
    /// Contract amount limits have not been configured
    AmountLimitsNotSet = 40,
    /// Contract fee configuration has not been set
    FeeConfigNotSet = 41,
    /// Merchant is suspended, banned, or closed in the configured marketplace
    MerchantNotTrading = 43,
    /// Configured marketplace could not be queried for merchant status
    MerchantStatusCheckFailed = 44,
    /// Conditional release requires a signed delivery proof
    SignedProofRequired = 45,
    /// Signed delivery proof does not match this escrow or valid delivery time
    InvalidSignedDeliveryProof = 46,
    /// Delivery oracle public key has not been configured by admin
    OraclePublicKeyNotSet = 47,
    /// Dual-control approval has not been configured for this escrow.
    DualControlNotConfigured = 48,
    /// Finance approval is required before a high-value release.
    SecondaryApprovalRequired = 49,
    /// Maximum treasuries exceeded
    MaxTreasuriesExceeded = 42,
    /// Escrow exists but no metadata was stored at creation
    MetadataNotSet = 400,
    /// Only one of order_hash/schema was supplied; metadata must be provided
    /// fully (both halves) or not at all (issue #38).
    InvalidMetadata = 401,
    /// Keeper bump rate limit exceeded (minimum time between bumps not elapsed)
    BumpRateLimitExceeded = 402,
    /// Escrow TTL not within threshold for bounty payout
    BumpThresholdNotMet = 403,
    /// No shipment proof recorded for this escrow
    ShipmentProofNotFound = 404,
    /// Scheduled fee update is not yet effective
    FeeUpdateNotEffective = 405,
    /// Minimum notice window for fee change not met
    FeeNoticeWindowNotMet = 406,
    /// Delivery Merkle proof is invalid or does not match the escrow order.
    InvalidMerkleProof = 407,
    /// A daily delivery Merkle root has already been published.
    MerkleRootAlreadyPublished = 408,
    /// A batch contains more items than the bounded batch limit.
    BatchLimitExceeded = 409,
    /// Dispute award amounts are negative or do not sum to the escrow balance.
    InvalidDisputeAward = 410,
}

/// Compact receipt returned to buyers after escrow creation via `get_receipt`.
///
/// Fields are a purposeful subset of `EscrowRecord` — callers that need the
/// full record (amount, token, timeout, …) should use `get_escrow` instead.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowReceipt {
    /// Numeric escrow identifier (matches the value returned by `deposit`).
    pub escrow_id: u64,
    /// Address of the buyer who funded the escrow.
    pub buyer: Address,
    /// Address of the seller (merchant) who will receive the released funds.
    pub seller: Address,
    /// Merchant-facing order reference embedded at deposit time.
    pub order_id: BytesN<32>,
    /// Current lifecycle status of the escrow.
    pub status: EscrowStatus,
}

/// Merchant-facing receipt for dashboards and settlement checks (issue #171).
///
/// `escrow_id` is the 32-byte order id (same correlation key as
/// [`ReleaseEligibility`]). `release_eligible` is computed read-only from
/// the current status and timeout without mutating state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerchantEscrowReceipt {
    pub escrow_id: BytesN<32>,
    pub merchant: Address,
    pub buyer: Address,
    pub status: EscrowStatus,
    pub release_eligible: bool,
}

/// Refund eligibility result returned by `get_refund_eligibility` (issue #173).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundEligibility {
    pub escrow_id: u64,
    pub eligible: bool,
    pub reason: Symbol,
}

/// Release eligibility result returned by `get_release_eligibility`.
///
/// `escrow_id` mirrors the escrow record's 32-byte order id so settlement
/// workers can correlate the read-only response with their backend job.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseEligibility {
    pub escrow_id: BytesN<32>,
    pub eligible: bool,
    pub reason: Symbol,
}

/// Read-only timeout metadata for a single escrow (issue #88).
///
/// Returned by [`EscrowContract::get_timeout_view`].  All fields are
/// derived from stored state and the current ledger sequence — the getter
/// never mutates contract storage.
///
/// # Fields
/// - `escrow_id`      — Numeric escrow identifier (matches `EscrowRecord.escrow_id`).
/// - `timeout_ledger` — Ledger sequence at which the buyer-refund timeout expires.
/// - `current_ledger` — Ledger sequence at the time this getter was invoked.
/// - `refundable`     — `true` when `current_ledger >= timeout_ledger` **and** the
///                      escrow is still in `Funded` status (buyer may refund).
///                      `false` for terminal states (Released / Refunded) or when
///                      the timeout has not yet been reached.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowTimeoutView {
    pub escrow_id: BytesN<32>,
    pub timeout_ledger: u32,
    pub current_ledger: u32,
    pub refundable: bool,
}

/// Complete read-only state snapshot for an escrow, returned by
/// `get_escrow_snapshot` (issue #329) so off-chain indexers can audit an
/// escrow's full state in a single call instead of replaying its event
/// history.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowSnapshot {
    pub record: EscrowRecord,
    pub fee_config: FeeConfig,
    pub current_ledger: u32,
    pub timed_out: bool,
    pub release_eligible: bool,
}

/// Monotonic yield snapshot returned by [`EscrowContract::get_accrued_yield`]
/// (issue #34).
///
/// All inputs needed for display are included so polling UIs cannot observe
/// decreasing yield.  `snapshot_ledger` anchors the read to a block-stable
/// point; `held_seconds` is computed from `created_at` to that ledger's
/// timestamp, making the result deterministic within a single ledger close.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YieldView {
    pub escrow_id: u64,
    pub principal: i128,
    pub apy_bps: u32,
    pub held_seconds: u64,
    pub accrued: i128,
    pub snapshot_ledger: u32,
}

/// Compact read-only escrow summary for API/indexer consumers (issue #90).
///
/// Returned by [`EscrowContract::get_escrow_summary`]. Contains all display
/// fields needed by the backend event indexer in a single call. The response
/// shape is identical for both terminal and non-terminal escrows — callers
/// do not need to branch on status to decode the result.
///
/// # Fields
/// - `escrow_id` — 32-byte order identifier (same correlation key used by
///   [`ReleaseEligibility`] and [`MerchantEscrowReceipt`]).
/// - `buyer`     — Address of the buyer who funded the escrow.
/// - `merchant`  — Address of the seller/merchant who receives released funds.
/// - `amount`    — Total escrowed token amount.
/// - `status`    — Current lifecycle status of the escrow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowSummary {
    pub escrow_id: BytesN<32>,
    pub buyer: Address,
    pub merchant: Address,
    pub amount: i128,
    pub status: EscrowStatus,
}

/// Paginated result returned by `list_escrows` and `list_escrows_by_buyer`
/// (issue #49). `items` contains up to `limit` escrow records starting at
/// `offset`. `total` is the total number of escrows in the queried index.
/// `next_offset` is `Some(offset + items.len())` when more records follow,
/// or `None` when the last page has been reached.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowListPage {
    pub items: soroban_sdk::Vec<EscrowRecord>,
    pub total: u32,
    pub next_offset: Option<u32>,
}

/// Maximum number of escrows returned in a single page from `list_escrows`
/// or `list_escrows_by_buyer`. Callers requesting a larger `limit` will
/// silently receive at most this many records.
pub const MAX_PAGE_LIMIT: u32 = 50;

/// Seconds in a 365-day year, used to prorate `YieldConfig::apr_bps` down to
/// the actual holding period of an escrow.
const SECONDS_PER_YEAR: i128 = 31_536_000;

/// Maximum number of treasury rows accepted by `set_fee_distribution`.
/// Keeps the fee-splitting loop bounded and prevents unbounded config growth.
const MAX_TREASURIES: u32 = 10;

/// Persistent TTL bump parameters (mirrors `marketplace`/`reputation`): any
/// entry whose remaining TTL is below the threshold is extended out to ~30
/// days of ledgers. Escrow records are long-lived by design — an open escrow
/// must not be evicted while funds are still locked.
const PERSISTENT_BUMP_THRESHOLD: u32 = 17_280; // ~1 day of ledgers (5s/ledger)
const PERSISTENT_BUMP_AMOUNT: u32 = 518_400; // ~30 days of ledgers

/// Minimum ledgers between bump_ttl_with_bounty calls to prevent bounty draining.
const BUMP_RATE_LIMIT_LEDGERS: u32 = 100;
/// TTL threshold (in ledgers) from expiration to qualify for bounty payout.
const BUMP_BOUNTY_THRESHOLD_LEDGERS: u32 = 17_280; // ~1 day
/// Keeper bounty amount instroked (small amount to incentivize maintenance).
const KEEPER_BOUNTY_AMOUNT: i128 = 1_000_000; // 1 XLM equivalent (assuming 7 decimal tokens)
/// Minimum ledgers of notice required before fee changes take effect.
const FEE_NOTICE_WINDOW_LEDGERS: u32 = 10_000;
/// Delay between an upgrade proposal and its earliest execution (48 hours).
pub const UPGRADE_TIMELOCK_SECS: u64 = 172_800;
/// Minimum (and default) number of admin approvals required to upgrade, so a
/// single compromised key can never replace contract code on its own.
pub const MIN_UPGRADE_THRESHOLD: u32 = 2;

fn check_not_terminal(record: &EscrowRecord) -> Result<(), EscrowError> {
    match record.status {
        EscrowStatus::Released => Err(EscrowError::AlreadyReleased),
        EscrowStatus::Refunded => Err(EscrowError::AlreadyRefunded),
        EscrowStatus::Cancelled => Err(EscrowError::AlreadyCancelled),
        _ => Ok(()),
    }
}

const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fn is_zero_address(env: &Env, address: &Address) -> bool {
    let zero_account = Address::from_str(env, ZERO_ACCOUNT_STRKEY);
    let zero_contract = Address::from_str(env, ZERO_CONTRACT_STRKEY);
    address == &zero_account || address == &zero_contract
}

#[contract]
pub struct EscrowContract;

// The `#[contractimpl]` macro generates client/wrapper functions that mirror
// the ABI entry-point signatures above; they cannot be annotated individually
// from user code, so the allow lives on the impl block for those generated
// wrappers only. User-defined functions carry their own scoped allows.
#[allow(clippy::too_many_arguments)]
#[contractimpl]
impl EscrowContract {
    /// Soroban constructor: initialize the escrow contract at deployment time with
    /// atomic admin + config setup. The host invokes this exactly once, so a later
    /// post-deploy `initialize` call cannot front-run a real deployer.
    pub fn __constructor(env: Env, config: EscrowConfig) -> Result<(), EscrowError> {
        Self::constructor(env, config)
    }

    /// Compatibility helper for tests and explicit deploy flows that call the
    /// function by name rather than via Soroban's auto-constructor path.
    pub fn constructor(env: Env, config: EscrowConfig) -> Result<(), EscrowError> {
        // Validate configuration
        if config.fee_bps > 1000 {
            return Err(EscrowError::InvalidFeeBps);
        }
        if config.min_amount <= 0 || config.max_amount < config.min_amount {
            return Err(EscrowError::InvalidLimits);
        }
        if is_zero_address(&env, &config.treasury) {
            return Err(EscrowError::InvalidAddress);
        }

        // Atomically store admin and configuration at deploy time
        env.storage().instance().set(&DataKey::Admin, &config.admin);
        env.storage().instance().set(&DataKey::LastEscrowId, &0u64);
        env.storage().instance().set(
            &DataKey::FeeConfig,
            &FeeConfig {
                fee_bps: config.fee_bps,
                treasury: config.treasury.clone(),
            },
        );
        env.storage().instance().set(
            &DataKey::AmountLimits,
            &EscrowAmountLimits {
                min_amount: config.min_amount,
                max_amount: config.max_amount,
            },
        );

        Ok(())
    }

    /// Initialize the escrow contract with the admin, fee config, and amount limits.
    ///
    /// # Deprecation Note
    /// For new deployments, prefer [`constructor`] which is called atomically at deploy time
    /// For new deployments, prefer [`__constructor`] which is called atomically at deploy time
    /// and cannot be front-run. This function exists for backward compatibility with legacy
    /// contracts deployed before the constructor pattern was available.
    pub fn initialize(
        env: Env,
        admin: Address,
        fee_bps: u32,
        treasury: Address,
        min_amount: i128,
        max_amount: i128,
    ) -> Result<bool, EscrowError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(EscrowError::AlreadyInitialized);
        }
        if fee_bps > 1000 {
            return Err(EscrowError::InvalidFeeBps);
        }
        if min_amount <= 0 || max_amount < min_amount {
            return Err(EscrowError::InvalidLimits);
        }
        if is_zero_address(&env, &treasury) {
            return Err(EscrowError::InvalidAddress);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::LastEscrowId, &0u64);
        env.storage()
            .instance()
            .set(&DataKey::FeeConfig, &FeeConfig { fee_bps, treasury });
        env.storage().instance().set(
            &DataKey::AmountLimits,
            &EscrowAmountLimits {
                min_amount,
                max_amount,
            },
        );
        // Keep the contract instance alive from deployment.
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        Ok(true)
    }

    /// Return the contract name and semantic version.
    /// Callable without authentication — safe for off-chain tooling.
    pub fn version(_env: Env) -> ContractVersion {
        ContractVersion {
            name: symbol_short!("escrow"),
            semver: symbol_short!("0_2_0"),
        }
    }

    /// Read-only version check for backend services to call before
    /// interacting with the contract (issue #325). Equivalent to `version`.
    pub fn check_version(env: Env) -> ContractVersion {
        Self::version(env)
    }

    /// Return the active primary admin and any pending primary admin transfer.
    /// Callable without authentication for backend health checks and deployment
    /// verification.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when the contract has not been initialized.
    pub fn get_admin(env: Env) -> Result<AdminView, EscrowError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        let pending_admin: Option<Address> = env.storage().instance().get(&DataKey::PendingAdmin);

        Ok(AdminView {
            admin,
            pending_admin,
        })
    }

    /// Set the number of admin approvals (M) required to execute an upgrade.
    /// Primary-admin only.
    ///
    /// The signer set (N) is the primary admin plus all co-admins.
    /// `threshold` must be at least [`MIN_UPGRADE_THRESHOLD`] and no greater
    /// than the current signer count. Changing the threshold while a proposal
    /// is pending is rejected so the bar cannot be lowered mid-flight.
    pub fn set_upgrade_threshold(
        env: Env,
        admin: Address,
        threshold: u32,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }
        if threshold < MIN_UPGRADE_THRESHOLD || threshold > Self::upgrade_signer_count(&env) {
            return Err(EscrowError::InvalidQuorum);
        }
        if Self::pending_upgrade_proposal(&env).is_some() {
            return Err(EscrowError::UpgradeProposalExists);
        }
        env.storage()
            .instance()
            .set(&DataKey::UpgradeThreshold, &threshold);
        Ok(true)
    }

    /// Number of admin approvals required to execute an upgrade.
    /// Defaults to [`MIN_UPGRADE_THRESHOLD`] when never configured.
    pub fn get_upgrade_threshold(env: Env) -> u32 {
        Self::upgrade_threshold(&env)
    }

    /// Return the current (pending or last executed) upgrade proposal, if any.
    pub fn get_upgrade_proposal(env: Env) -> Option<UpgradeProposal> {
        env.storage().instance().get(&DataKey::UpgradeProposal)
    }

    /// Propose upgrading the contract to `new_wasm_hash`. Admin or co-admin.
    ///
    /// Starts the [`UPGRADE_TIMELOCK_SECS`] timelock and counts as the
    /// proposer's own approval. Only one unexecuted proposal may exist at a
    /// time; cancel it first to propose a different hash.
    pub fn propose_upgrade(
        env: Env,
        proposer: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<bool, EscrowError> {
        proposer.require_auth();
        if !Self::is_admin(env.clone(), proposer.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if Self::pending_upgrade_proposal(&env).is_some() {
            return Err(EscrowError::UpgradeProposalExists);
        }

        let proposed_at = env.ledger().timestamp();
        let mut approvals = Vec::new(&env);
        approvals.push_back(proposer.clone());
        let proposal = UpgradeProposal {
            new_wasm_hash: new_wasm_hash.clone(),
            proposed_at,
            approvals,
            executed: false,
        };
        env.storage()
            .instance()
            .set(&DataKey::UpgradeProposal, &proposal);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("upg_prop")),
            ContractUpgradeProposedEvent {
                proposer,
                new_wasm_hash,
                proposed_at,
                executable_at: proposed_at.saturating_add(UPGRADE_TIMELOCK_SECS),
                threshold: Self::upgrade_threshold(&env),
            },
        );
        Ok(true)
    }

    /// Approve the pending upgrade proposal. Admin or co-admin.
    ///
    /// `new_wasm_hash` must match the pending proposal so an approval can
    /// never be applied to a proposal that was swapped out after review.
    pub fn approve_upgrade(
        env: Env,
        approver: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<bool, EscrowError> {
        approver.require_auth();
        if !Self::is_admin(env.clone(), approver.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        let mut proposal =
            Self::pending_upgrade_proposal(&env).ok_or(EscrowError::UpgradeProposalNotFound)?;
        if proposal.new_wasm_hash != new_wasm_hash {
            return Err(EscrowError::UpgradeHashMismatch);
        }
        if proposal.approvals.contains(&approver) {
            return Err(EscrowError::AlreadyVoted);
        }
        proposal.approvals.push_back(approver.clone());
        env.storage()
            .instance()
            .set(&DataKey::UpgradeProposal, &proposal);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("upg_appr")),
            ContractUpgradeApprovedEvent {
                approver,
                new_wasm_hash,
                approval_count: Self::valid_upgrade_approvals(&env, &proposal.approvals),
                threshold: Self::upgrade_threshold(&env),
            },
        );
        Ok(true)
    }

    /// Cancel the pending upgrade proposal. Any admin or co-admin may veto.
    pub fn cancel_upgrade(env: Env, caller: Address) -> Result<bool, EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        let proposal =
            Self::pending_upgrade_proposal(&env).ok_or(EscrowError::UpgradeProposalNotFound)?;
        env.storage().instance().remove(&DataKey::UpgradeProposal);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("upg_cncl")),
            ContractUpgradeCancelledEvent {
                cancelled_by: caller,
                new_wasm_hash: proposal.new_wasm_hash,
            },
        );
        Ok(true)
    }

    /// Execute the pending multi-sig upgrade to `new_wasm_hash`. Admin or
    /// co-admin (issue #292).
    ///
    /// Requires a pending proposal for the same hash, at least
    /// `get_upgrade_threshold()` approvals from addresses that are *still*
    /// admins, and that [`UPGRADE_TIMELOCK_SECS`] has elapsed since the
    /// proposal was submitted. A single key can therefore never replace the
    /// contract code unilaterally.
    ///
    /// Persistent storage (escrows, admin list, fee config, …) is keyed by
    /// contract instance and is unaffected by an upgrade — only the
    /// executable code changes, so existing escrows remain functional
    /// afterwards. Sets the migration flag and emits
    /// [`ContractUpgradedEvent`] so backend services can detect the version
    /// change.
    pub fn upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        let mut proposal =
            Self::pending_upgrade_proposal(&env).ok_or(EscrowError::UpgradeProposalNotFound)?;
        if proposal.new_wasm_hash != new_wasm_hash {
            return Err(EscrowError::UpgradeHashMismatch);
        }
        if env.ledger().timestamp() < proposal.proposed_at.saturating_add(UPGRADE_TIMELOCK_SECS) {
            return Err(EscrowError::UpgradeTimelockActive);
        }
        if Self::valid_upgrade_approvals(&env, &proposal.approvals) < Self::upgrade_threshold(&env)
        {
            return Err(EscrowError::QuorumNotReached);
        }

        proposal.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::UpgradeProposal, &proposal);

        let previous_semver = Self::version(env.clone()).semver;

        env.storage().instance().set(&DataKey::MigrationFlag, &true);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("upgraded")),
            ContractUpgradedEvent {
                admin,
                previous_semver,
                new_wasm_hash: new_wasm_hash.clone(),
            },
        );

        env.deployer().update_current_contract_wasm(new_wasm_hash);

        Ok(true)
    }

    /// Returns true once the contract has been upgraded at least once via `upgrade`.
    pub fn is_migrated(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::MigrationFlag)
            .unwrap_or(false)
    }

    /// Set the escrow amount limits. Admin-only.
    pub fn set_limits(
        env: Env,
        admin: Address,
        min_amount: i128,
        max_amount: i128,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if min_amount <= 0 || max_amount < min_amount {
            return Err(EscrowError::InvalidLimits);
        }
        env.storage().instance().set(
            &DataKey::AmountLimits,
            &EscrowAmountLimits {
                min_amount,
                max_amount,
            },
        );
        Ok(true)
    }

    /// Get the current escrow amount limits.
    ///
    /// # Errors
    /// Returns [`EscrowError::AmountLimitsNotSet`] when the contract has not
    /// been initialized with amount limits yet.
    pub fn get_limits(env: Env) -> Result<EscrowAmountLimits, EscrowError> {
        env.storage()
            .instance()
            .get(&DataKey::AmountLimits)
            .ok_or(EscrowError::AmountLimitsNotSet)
    }

    /// Configure the finance approver for a high-value escrow. Admin-only.
    pub fn set_dual_control_config(
        env: Env,
        admin: Address,
        escrow_id: u64,
        secondary_approver: Address,
    ) -> Result<(), EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        if record.amount <= DUAL_CONTROL_THRESHOLD {
            return Err(EscrowError::InvalidAmount);
        }

        env.storage().persistent().set(
            &DataKey::DualControlConfig(escrow_id),
            &DualControlConfig {
                secondary_approver,
                is_secondary_approved: false,
                secondary_approved_at: 0,
            },
        );
        Ok(())
    }

    /// Record explicit finance authorization for a configured high-value escrow.
    pub fn approve_release(
        env: Env,
        escrow_id: u64,
        secondary_approver: Address,
    ) -> Result<bool, EscrowError> {
        let config_key = DataKey::DualControlConfig(escrow_id);
        let mut config: DualControlConfig = env
            .storage()
            .persistent()
            .get(&config_key)
            .ok_or(EscrowError::DualControlNotConfigured)?;
        if config.secondary_approver != secondary_approver {
            return Err(EscrowError::Unauthorized);
        }
        secondary_approver.require_auth();

        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(EscrowError::NotFound)?;
        if record.amount <= DUAL_CONTROL_THRESHOLD || record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        config.is_secondary_approved = true;
        config.secondary_approved_at = env.ledger().timestamp();
        env.storage().persistent().set(&config_key, &config);
        Ok(true)
    }

    /// Set the quorum configuration for dispute resolution. Admin-only.
    pub fn set_quorum_config(
        env: Env,
        admin: Address,
        arbiters: soroban_sdk::Vec<Address>,
        threshold: u32,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if threshold == 0 || threshold > arbiters.len() {
            return Err(EscrowError::InvalidQuorum);
        }
        // Check for duplicate arbiters
        let mut unique_arbiters = soroban_sdk::Vec::new(&env);
        for arbiter in arbiters.iter() {
            if unique_arbiters.contains(&arbiter) {
                return Err(EscrowError::InvalidQuorum);
            }
            unique_arbiters.push_back(arbiter);
        }
        let quorum_config = QuorumConfig {
            arbiters: unique_arbiters,
            threshold,
        };
        env.storage()
            .instance()
            .set(&DataKey::QuorumConfig, &quorum_config);
        Ok(true)
    }

    /// Get the current quorum configuration.
    pub fn get_quorum_config(env: Env) -> Result<QuorumConfig, EscrowError> {
        env.storage()
            .instance()
            .get(&DataKey::QuorumConfig)
            .ok_or(EscrowError::QuorumConfigNotSet)
    }

    /// Vote on a disputed escrow. Only authorized arbiters.
    pub fn vote_dispute(
        env: Env,
        escrow_id: u64,
        arbiter: Address,
        release_to_seller: bool,
    ) -> Result<bool, EscrowError> {
        arbiter.require_auth();

        let quorum_config: QuorumConfig = env
            .storage()
            .instance()
            .get(&DataKey::QuorumConfig)
            .ok_or(EscrowError::QuorumConfigNotSet)?;
        if !quorum_config.arbiters.contains(&arbiter) {
            return Err(EscrowError::NotAnArbiter);
        }

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };
        if record.status != EscrowStatus::Disputed {
            return Err(EscrowError::NotDisputed);
        }

        let votes_key = DataKey::DisputeVotes(escrow_id);
        let mut votes: soroban_sdk::Vec<DisputeVote> = env
            .storage()
            .persistent()
            .get(&votes_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));

        if votes.iter().any(|vote| vote.arbiter == arbiter) {
            return Err(EscrowError::AlreadyVoted);
        }

        votes.push_back(DisputeVote {
            arbiter: arbiter.clone(),
            release_to_seller,
        });
        env.storage().persistent().set(&votes_key, &votes);

        // Compute live tallies so the event reflects the state *after* this vote.
        let votes_for = votes.iter().filter(|v| v.release_to_seller).count() as u32;

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("vote"), escrow_id),
            DisputeVotedEvent {
                escrow_id,
                arbiter,
                release_to_seller,
                votes_for,
                threshold: quorum_config.threshold,
            },
        );

        Ok(true)
    }

    /// Get votes for a disputed escrow.
    pub fn get_dispute_votes(env: Env, escrow_id: u64) -> soroban_sdk::Vec<DisputeVote> {
        let votes_key = DataKey::DisputeVotes(escrow_id);
        env.storage()
            .persistent()
            .get(&votes_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Resolve a disputed escrow via quorum.
    pub fn resolve_dispute_quorum(
        env: Env,
        escrow_id: u64,
        caller: Address,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };
        if record.status != EscrowStatus::Disputed {
            return Err(EscrowError::NotDisputed);
        }

        let quorum_config: QuorumConfig = env
            .storage()
            .instance()
            .get(&DataKey::QuorumConfig)
            .ok_or(EscrowError::QuorumConfigNotSet)?;
        let votes_key = DataKey::DisputeVotes(escrow_id);
        let votes: soroban_sdk::Vec<DisputeVote> = env
            .storage()
            .persistent()
            .get(&votes_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));

        // Only count votes from current arbiters
        let seller_votes = votes
            .iter()
            .filter(|v| v.release_to_seller && quorum_config.arbiters.contains(&v.arbiter))
            .count() as u32;
        let buyer_votes = votes
            .iter()
            .filter(|v| !v.release_to_seller && quorum_config.arbiters.contains(&v.arbiter))
            .count() as u32;

        // Handle conflicting quorum outcomes explicitly
        let release_to_seller =
            if seller_votes >= quorum_config.threshold && buyer_votes >= quorum_config.threshold {
                return Err(EscrowError::ConflictingQuorum);
            } else if seller_votes >= quorum_config.threshold {
                true
            } else if buyer_votes >= quorum_config.threshold {
                false
            } else {
                return Err(EscrowError::QuorumNotReached);
            };

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        if release_to_seller {
            let payout = Self::compute_payout(&env, record.amount)?;
            Self::distribute_fee(&env, &token_client, payout.fee)?;
            token_client.transfer(
                &env.current_contract_address(),
                &record.seller,
                &payout.seller_net,
            );
            record.status = EscrowStatus::Released;
        } else {
            token_client.transfer(
                &env.current_contract_address(),
                &record.buyer,
                &record.amount,
            );
            record.status = EscrowStatus::Refunded;
        }

        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().remove(&votes_key);
        env.storage()
            .persistent()
            .remove(&DataKey::TimeoutExtensionVotes(escrow_id));

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("resolved"),
                escrow_id,
            ),
            EscrowResolvedEvent {
                escrow_id,
                release_to_seller,
                resolved_by: caller,
            },
        );

        Ok(true)
    }

    /// Vote to extend the refund timeout of an escrow via arbiter quorum.
    ///
    /// Any arbiter configured in [`QuorumConfig`] may cast one vote per
    /// escrow proposing an `extension_ledgers` amount. Once at least
    /// `threshold` arbiters have voted for the *same* `extension_ledgers`
    /// value, the escrow's `timeout_ledger` is pushed back by that amount,
    /// a [`TimeoutExtendedEvent`] is published, and the vote log is cleared
    /// so arbiters can vote again for a future extension.
    ///
    /// Requires the escrow to not be in a terminal state (Released,
    /// Refunded, Cancelled). Each arbiter may vote only once per round.
    pub fn extend_timeout_via_quorum(
        env: Env,
        escrow_id: u64,
        arbiter: Address,
        extension_ledgers: u32,
    ) -> Result<bool, EscrowError> {
        arbiter.require_auth();

        if extension_ledgers == 0 {
            return Err(EscrowError::InvalidExtension);
        }

        let quorum_config: QuorumConfig = env
            .storage()
            .instance()
            .get(&DataKey::QuorumConfig)
            .ok_or(EscrowError::QuorumConfigNotSet)?;
        if !quorum_config.arbiters.contains(&arbiter) {
            return Err(EscrowError::NotAnArbiter);
        }

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };
        check_not_terminal(&record)?;

        let votes_key = DataKey::TimeoutExtensionVotes(escrow_id);
        let mut votes: soroban_sdk::Vec<TimeoutExtensionVote> = env
            .storage()
            .persistent()
            .get(&votes_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));

        if votes.iter().any(|vote| vote.arbiter == arbiter) {
            return Err(EscrowError::AlreadyVoted);
        }

        votes.push_back(TimeoutExtensionVote {
            arbiter,
            extension_ledgers,
            voted_at: env.ledger().timestamp(),
        });

        let matching_votes = votes
            .iter()
            .filter(|vote| vote.extension_ledgers == extension_ledgers)
            .count() as u32;

        if matching_votes < quorum_config.threshold {
            env.storage().persistent().set(&votes_key, &votes);
            return Ok(false);
        }

        let previous_timeout_ledger = record.timeout_ledger;
        let new_timeout_ledger = previous_timeout_ledger.saturating_add(extension_ledgers);
        record.timeout_ledger = new_timeout_ledger;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().remove(&votes_key);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("tmo_ext"), escrow_id),
            TimeoutExtendedEvent {
                escrow_id,
                previous_timeout_ledger,
                new_timeout_ledger,
                extension_ledgers,
            },
        );

        Ok(true)
    }

    /// Get the recorded timeout-extension votes for an escrow's current round.
    pub fn get_timeout_extension_votes(
        env: Env,
        escrow_id: u64,
    ) -> soroban_sdk::Vec<TimeoutExtensionVote> {
        let votes_key = DataKey::TimeoutExtensionVotes(escrow_id);
        env.storage()
            .persistent()
            .get(&votes_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Update the fee percentage. Admin-only.
    pub fn update_fee(env: Env, admin: Address, new_fee_bps: u32) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if new_fee_bps > 1000 {
            return Err(EscrowError::InvalidFeeBps);
        }
        let mut fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
        fee_config.fee_bps = new_fee_bps;
        env.storage()
            .instance()
            .set(&DataKey::FeeConfig, &fee_config);
        Ok(true)
    }

    /// Get the current fee configuration.
    ///
    /// # Errors
    /// Returns [`EscrowError::FeeConfigNotSet`] when the contract has not
    /// been initialized with fee configuration yet.
    pub fn get_fee_config(env: Env) -> Result<FeeConfig, EscrowError> {
        // Check for pending scheduled update that is now effective
        let current_ledger = env.ledger().sequence();
        if let Some(scheduled) = env
            .storage()
            .instance()
            .get::<_, ScheduledFeeUpdate>(&DataKey::ScheduledFeeUpdate)
        {
            if current_ledger >= scheduled.effective_ledger {
                // Apply the scheduled update
                let mut fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
                fee_config.fee_bps = scheduled.fee_bps;
                fee_config.treasury = scheduled.treasury.clone();
                env.storage()
                    .instance()
                    .set(&DataKey::FeeConfig, &fee_config);
                // Clear the scheduled update
                env.storage()
                    .instance()
                    .remove(&DataKey::ScheduledFeeUpdate);
                return Ok(fee_config);
            }
        }

        env.storage()
            .instance()
            .get(&DataKey::FeeConfig)
            .ok_or(EscrowError::FeeConfigNotSet)
    }

    /// Schedule a fee update to take effect after the minimum notice window.
    ///
    /// Requires admin authentication and enforces a minimum notice period
    /// of 10,000 ledgers before the new fee takes effect.
    /// Emits [`ConfigChangeScheduledEvent`] when scheduled.
    pub fn schedule_fee_update(
        env: Env,
        admin: Address,
        new_fee_bps: u32,
        new_treasury: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if new_fee_bps > 1000 {
            return Err(EscrowError::InvalidFeeBps);
        }
        if is_zero_address(&env, &new_treasury) {
            return Err(EscrowError::InvalidAddress);
        }

        let current_ledger = env.ledger().sequence();
        let effective_ledger = current_ledger
            .checked_add(FEE_NOTICE_WINDOW_LEDGERS)
            .ok_or(EscrowError::InvalidExtension)?;

        let scheduled = ScheduledFeeUpdate {
            fee_bps: new_fee_bps,
            treasury: new_treasury.clone(),
            effective_ledger,
            scheduled_at_ledger: current_ledger,
        };
        env.storage()
            .instance()
            .set(&DataKey::ScheduledFeeUpdate, &scheduled);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("fee_sched")),
            ConfigChangeScheduledEvent {
                fee_bps: new_fee_bps,
                treasury: new_treasury,
                effective_ledger,
                scheduled_at_ledger: current_ledger,
                scheduled_by: admin,
            },
        );

        Ok(true)
    }

    /// Get any pending scheduled fee update.
    pub fn get_scheduled_fee_update(env: Env) -> Option<ScheduledFeeUpdate> {
        env.storage()
            .instance()
            .get(&DataKey::ScheduledFeeUpdate)
    }

    /// Extend an escrow's TTL and pay a small keeper bounty if within threshold.
    ///
    /// This function allows keepers to extend escrows that are close to expiration
    /// (within `BUMP_BOUNTY_THRESHOLD_LEDGERS` of their timeout). If the escrow
    /// is within this threshold, a small bounty is paid to the keeper address.
    ///
    /// Rate limiting is enforced to prevent bounty draining - a keeper cannot
    /// call this function more frequently than `BUMP_RATE_LIMIT_LEDGERS`.
    ///
    /// # Arguments
    /// * `escrow_id` - The ID of the escrow to bump
    /// * `keeper` - Address that receives the bounty and called the function
    ///
    /// # Returns
    /// * `true` if TTL was extended and bounty paid
    /// * `false` if TTL was extended but escrow was not within bounty threshold
    ///
    /// # Errors
    /// Returns [`EscrowError::BumpRateLimitExceeded`] if called too soon after last bump.
    /// Returns [`EscrowError::NotFound`] if escrow does not exist.
    /// Returns [`EscrowError::InvalidStatus`] if escrow is in a terminal state.
    pub fn bump_ttl_with_bounty(
        env: Env,
        escrow_id: u64,
        keeper: Address,
    ) -> Result<bool, EscrowError> {
        keeper.require_auth();

        // Check rate limiting
        let current_ledger = env.ledger().sequence();
        let last_bump: u32 = env
            .storage()
            .instance()
            .get(&DataKey::LastBumpLedger(escrow_id))
            .unwrap_or(0);
        if current_ledger.saturating_sub(last_bump) < BUMP_RATE_LIMIT_LEDGERS {
            return Err(EscrowError::BumpRateLimitExceeded);
        }

        // Get and validate escrow
        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };
        check_not_terminal(&record)?;

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        // Calculate ledgers until timeout
        let ledgers_until_timeout = record
            .timeout_ledger
            .saturating_sub(current_ledger);

        // Extend TTL by the bump amount (30 days)
        let extension = PERSISTENT_BUMP_AMOUNT;
        let old_timeout = record.timeout_ledger;
        record.timeout_ledger = record.timeout_ledger.saturating_add(extension);
        record.updated_at = env.ledger().timestamp();

        // Update storage
        env.storage().persistent().set(&key, &record);
        env.storage()
            .instance()
            .set(&DataKey::LastBumpLedger(escrow_id), &current_ledger);

        // Extend TTL of the escrow record
        let storage = env.storage().persistent();
        storage.extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);

        // Check if within bounty threshold and pay bounty
        let bounty_paid = if ledgers_until_timeout <= BUMP_BOUNTY_THRESHOLD_LEDGERS
            && ledgers_until_timeout > 0
        {
            let remaining = record.amount - record.released_amount - record.refunded_amount;
            if remaining >= KEEPER_BOUNTY_AMOUNT {
                let token_client = soroban_sdk::token::Client::new(&env, &record.token);
                token_client.transfer(
                    &env.current_contract_address(),
                    &keeper,
                    &KEEPER_BOUNTY_AMOUNT,
                );

                env.events().publish(
                    (symbol_short!("escrow"), symbol_short!("bounty"), escrow_id),
                    KeeperBountyPaidEvent {
                        escrow_id,
                        keeper: keeper.clone(),
                        bounty_amount: KEEPER_BOUNTY_AMOUNT,
                        new_timeout_ledger: record.timeout_ledger,
                    },
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        // Emit timeout extended event
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("tmo_ext"), escrow_id),
            EscrowTimeoutExtendedEvent {
                escrow_id,
                old_timeout_ledger: old_timeout,
                new_timeout_ledger: record.timeout_ledger,
                extended_by: keeper,
            },
        );

        Ok(bounty_paid)
    }

    /// Record an on-chain shipment proof for an escrow.
    ///
    /// This proof is required for sellers to claim funds on timeout.
    /// Without a recorded proof, only the buyer can claim a refund on timeout.
    pub fn record_shipment_proof(
        env: Env,
        escrow_id: u64,
        caller: Address,
        carrier: Symbol,
        tracking_hash: BytesN<32>,
        shipped_at: u64,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        // Only seller can record shipment proof
        if caller != record.seller {
            return Err(EscrowError::Unauthorized);
        }

        // Validate shipment timestamp is reasonable
        if shipped_at < record.created_at || shipped_at > env.ledger().timestamp() {
            return Err(EscrowError::InvalidSignedDeliveryProof);
        }

        let proof = ShipmentProof {
            escrow_id,
            carrier,
            tracking_hash,
            shipped_at,
            recorded_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::ShipmentProof(escrow_id), &proof);

        // Extend TTL for the proof
        let storage = env.storage().persistent();
        storage.extend_ttl(
            &DataKey::ShipmentProof(escrow_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        Ok(true)
    }

    /// Get shipment proof for an escrow.
    pub fn get_shipment_proof(env: Env, escrow_id: u64) -> Result<ShipmentProof, EscrowError> {
        env.storage()
            .persistent()
            .get(&DataKey::ShipmentProof(escrow_id))
            .ok_or(EscrowError::ShipmentProofNotFound)
    }

    /// Check if an escrow has a valid shipment proof.
    pub fn has_shipment_proof(env: Env, escrow_id: u64) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::ShipmentProof(escrow_id))
    }

    /// Configure the release fee to be split across multiple treasuries. Admin-only.
    ///
    /// The combined `bps` across all shares must not exceed 1000 (10%). Once
    /// set, `resolve_dispute` and `resolve_dispute_quorum` pay each treasury
    /// its configured share instead of the single treasury in `FeeConfig`.
    /// Passing an empty vector reverts to the single-treasury `FeeConfig`.
    pub fn set_fee_distribution(
        env: Env,
        admin: Address,
        shares: soroban_sdk::Vec<TreasuryShare>,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        if shares.len() > MAX_TREASURIES {
            return Err(EscrowError::MaxTreasuriesExceeded);
        }

        let mut total_bps: u32 = 0;
        for share in shares.iter() {
            if is_zero_address(&env, &share.treasury) {
                return Err(EscrowError::InvalidAddress);
            }
            if share.bps == 0 {
                return Err(EscrowError::InvalidFeeBps);
            }
            total_bps = total_bps
                .checked_add(share.bps)
                .ok_or(EscrowError::InvalidFeeBps)?;
        }
        if total_bps > 1000 {
            return Err(EscrowError::InvalidFeeBps);
        }

        env.storage()
            .instance()
            .set(&DataKey::FeeDistribution, &shares);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("feedist")),
            FeeDistributionSetEvent {
                admin,
                treasury_count: shares.len(),
                total_bps,
            },
        );

        Ok(true)
    }

    /// Get the current multi-treasury fee distribution. Empty when unset
    /// (i.e. the single-treasury `FeeConfig` is in effect).
    pub fn get_fee_distribution(env: Env) -> soroban_sdk::Vec<TreasuryShare> {
        env.storage()
            .instance()
            .get(&DataKey::FeeDistribution)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Computes and transfers the release fee out of `amount`, splitting it
    /// across the configured multi-treasury distribution when one is set,
    /// falling back to the single-treasury `FeeConfig` otherwise. Returns
    /// the total fee amount deducted.
    fn distribute_fee(
        env: &Env,
        token_client: &soroban_sdk::token::Client,
        total_fee: i128,
    ) -> Result<(), EscrowError> {
        if total_fee == 0 {
            return Ok(());
        }

        let shares: soroban_sdk::Vec<TreasuryShare> = env
            .storage()
            .instance()
            .get(&DataKey::FeeDistribution)
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));

        if shares.is_empty() {
            let fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
            token_client.transfer(
                &env.current_contract_address(),
                &fee_config.treasury,
                &total_fee,
            );
        } else {
            let mut total_bps: i128 = 0;
            for share in shares.iter() {
                total_bps += share.bps as i128;
            }

            let mut distributed: i128 = 0;
            let last_idx = shares.len() - 1;

            for (i, share) in shares.iter().enumerate() {
                if i as u32 == last_idx {
                    let remaining = total_fee - distributed;
                    if remaining > 0 {
                        token_client.transfer(
                            &env.current_contract_address(),
                            &share.treasury,
                            &remaining,
                        );
                    }
                } else {
                    let bps = share.bps as i128;
                    let fee = (total_fee * bps) / total_bps;
                    if fee > 0 {
                        token_client.transfer(
                            &env.current_contract_address(),
                            &share.treasury,
                            &fee,
                        );
                        distributed += fee;
                    }
                }
            }
        }
        Ok(())
    }

    /// Computes the total release fee (in tokens) for `amount`, splitting it
    /// across the configured multi-treasury distribution when one is set,
    /// falling back to the single-treasury `FeeConfig` otherwise. Never
    /// transfers tokens and never panics on a missing config: returns
    /// `FeeConfigNotSet` when no config exists.
    fn compute_fee_amount(env: &Env, amount: i128) -> Result<i128, EscrowError> {
        let shares: soroban_sdk::Vec<TreasuryShare> = env
            .storage()
            .instance()
            .get(&DataKey::FeeDistribution)
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));

        if !shares.is_empty() {
            let mut total_fee: i128 = 0;
            for share in shares.iter() {
                let bps = share.bps as i128;
                total_fee +=
                    (amount / 10_000i128) * bps + ((amount % 10_000i128) * bps) / 10_000i128;
            }
            Ok(total_fee)
        } else {
            let fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
            let fee_bps = fee_config.fee_bps as i128;
            Ok((amount / 10_000i128) * fee_bps + ((amount % 10_000i128) * fee_bps) / 10_000i128)
        }
    }

    /// Computes the net seller payout and platform fee for `amount` (issue #27).
    /// Pure calculation — see `distribute_fee` for the transfer side.
    fn compute_payout(env: &Env, amount: i128) -> Result<ReleasePayout, EscrowError> {
        let fee = Self::compute_fee_amount(env, amount)?;
        let fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
        Ok(ReleasePayout {
            seller_net: amount - fee,
            fee,
            treasury: fee_config.treasury,
        })
    }

    /// Add a token to the escrow whitelist. Admin-only.
    pub fn add_token(
        env: Env,
        admin: Address,
        token_address: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        if Self::is_token_allowed(env.clone(), token_address.clone()) {
            return Ok(true);
        }

        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowedTokenCount)
            .unwrap_or(0);

        env.storage()
            .instance()
            .set(&DataKey::AllowedToken(token_address.clone()), &count);
        env.storage()
            .instance()
            .set(&DataKey::AllowedTokenAt(count), &token_address);
        env.storage()
            .instance()
            .set(&DataKey::AllowedTokenCount, &(count + 1));

        Ok(true)
    }

    /// Remove a token from the escrow whitelist. Admin-only.
    pub fn remove_token(
        env: Env,
        admin: Address,
        token_address: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        let index_opt: Option<u32> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedToken(token_address.clone()));

        if let Some(idx) = index_opt {
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::AllowedTokenCount)
                .unwrap_or(0);

            if count > 0 {
                let last_idx = count - 1;
                if idx != last_idx {
                    // Swap with the last element
                    let last_token: Address = env
                        .storage()
                        .instance()
                        .get(&DataKey::AllowedTokenAt(last_idx))
                        .unwrap();
                    env.storage()
                        .instance()
                        .set(&DataKey::AllowedTokenAt(idx), &last_token);
                    env.storage()
                        .instance()
                        .set(&DataKey::AllowedToken(last_token), &idx);
                }

                // Remove the target token from mappings
                env.storage()
                    .instance()
                    .remove(&DataKey::AllowedToken(token_address));
                env.storage()
                    .instance()
                    .remove(&DataKey::AllowedTokenAt(last_idx));
                env.storage()
                    .instance()
                    .set(&DataKey::AllowedTokenCount, &last_idx);
            }
        }

        Ok(true)
    }

    /// Returns true when the token is approved for escrow deposits.
    pub fn is_token_allowed(env: Env, token_address: Address) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::AllowedToken(token_address))
    }

    /// List all tokens currently approved for escrow deposits.
    pub fn list_tokens(env: Env) -> soroban_sdk::Vec<Address> {
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowedTokenCount)
            .unwrap_or(0);

        Self::list_tokens_paginated(env, 0, count)
    }

    /// List tokens currently approved for escrow deposits with pagination.
    pub fn list_tokens_paginated(env: Env, offset: u32, limit: u32) -> soroban_sdk::Vec<Address> {
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowedTokenCount)
            .unwrap_or(0);

        let mut tokens = soroban_sdk::Vec::new(&env);
        let end = count.min(offset.saturating_add(limit));

        for i in offset..end {
            if let Some(token) = env.storage().instance().get(&DataKey::AllowedTokenAt(i)) {
                tokens.push_back(token);
            }
        }
        tokens
    }

    /// Fund the shared liquidity pool for a token so it can back instant
    /// settlements via `settle_from_pool`. Any account may contribute
    /// liquidity for a whitelisted token.
    pub fn fund_pool(
        env: Env,
        funder: Address,
        token: Address,
        amount: i128,
    ) -> Result<i128, EscrowError> {
        funder.require_auth();

        if !Self::is_token_allowed(env.clone(), token.clone()) {
            return Err(EscrowError::TokenNotWhitelisted);
        }
        if amount <= 0 {
            return Err(EscrowError::InvalidAmount);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&funder, &env.current_contract_address(), &amount);

        let pool_key = DataKey::LiquidityPool(token.clone());
        let mut pool: LiquidityPool =
            env.storage()
                .instance()
                .get(&pool_key)
                .unwrap_or(LiquidityPool {
                    token: token.clone(),
                    balance: 0,
                });
        pool.balance += amount;
        env.storage().instance().set(&pool_key, &pool);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("pl_fund")),
            PoolFundedEvent {
                token,
                funder,
                amount,
                new_balance: pool.balance,
            },
        );

        Ok(pool.balance)
    }

    /// Withdraw liquidity from a token's pool. Admin-only.
    pub fn withdraw_from_pool(
        env: Env,
        admin: Address,
        token: Address,
        amount: i128,
    ) -> Result<i128, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if amount <= 0 {
            return Err(EscrowError::InvalidAmount);
        }

        let pool_key = DataKey::LiquidityPool(token.clone());
        let mut pool: LiquidityPool = env
            .storage()
            .instance()
            .get(&pool_key)
            .ok_or(EscrowError::PoolNotFound)?;

        if amount > pool.balance {
            return Err(EscrowError::InsufficientPoolBalance);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &admin, &amount);

        pool.balance -= amount;
        env.storage().instance().set(&pool_key, &pool);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("pl_wdrw")),
            PoolWithdrawnEvent {
                token,
                admin,
                amount,
                new_balance: pool.balance,
            },
        );

        Ok(pool.balance)
    }

    /// Instantly settle a funded escrow by paying the seller out of the
    /// shared liquidity pool for that escrow's token, instead of going
    /// through the ordinary buyer/admin-triggered `release` flow. Admin-only.
    ///
    /// The settled amount is debited from the pool's tracked balance so that
    /// `pool.balance` always reflects real, currently unencumbered liquidity
    /// and a later `withdraw_from_pool` cannot over-commit the same tokens.
    pub fn settle_from_pool(
        env: Env,
        escrow_id: u64,
        caller: Address,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        if remaining <= 0 {
            return Err(EscrowError::ZeroAmount);
        }

        let pool_key = DataKey::LiquidityPool(record.token.clone());
        let mut pool: LiquidityPool = env
            .storage()
            .instance()
            .get(&pool_key)
            .ok_or(EscrowError::PoolNotFound)?;
        if pool.balance < remaining {
            return Err(EscrowError::InsufficientPoolBalance);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        token_client.transfer(&env.current_contract_address(), &record.seller, &remaining);

        pool.balance = pool
            .balance
            .checked_sub(remaining)
            .ok_or(EscrowError::InsufficientPoolBalance)?;
        env.storage().instance().set(&pool_key, &pool);

        record.released_amount += remaining;
        record.status = EscrowStatus::Released;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("pl_stl"), escrow_id),
            PoolSettledEvent {
                escrow_id,
                token: record.token.clone(),
                seller: record.seller.clone(),
                amount: remaining,
            },
        );

        Ok(true)
    }

    /// Read-only getter for a token's liquidity pool balance.
    ///
    /// # Errors
    /// Returns [`EscrowError::PoolNotFound`] when no pool has ever been funded
    /// for the given token, so callers can distinguish an unfunded pool from a
    /// funded one that is currently empty.
    pub fn get_liquidity_pool(env: Env, token: Address) -> Result<LiquidityPool, EscrowError> {
        env.storage()
            .instance()
            .get(&DataKey::LiquidityPool(token))
            .ok_or(EscrowError::PoolNotFound)
    }

    /// Publish a delivery Merkle root for a UTC date.
    ///
    /// Only the primary admin or a co-admin may publish roots. Dates are
    /// represented as Unix epoch days. A stored root cannot be replaced;
    /// reads and proof submissions refresh its persistent-storage TTL.
    pub fn publish_merkle_root(
        env: Env,
        caller: Address,
        date: u64,
        root: BytesN<32>,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::MerkleRoot(date);
        if env.storage().persistent().has(&key) {
            return Err(EscrowError::MerkleRootAlreadyPublished);
        }
        env.storage().persistent().set(&key, &root);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("merkroot"), date),
            root,
        );
        Ok(true)
    }

    /// Return the published delivery root for a UTC epoch date, if present.
    pub fn get_merkle_root(env: Env, date: u64) -> Option<BytesN<32>> {
        let key = DataKey::MerkleRoot(date);
        let root = env.storage().persistent().get(&key);
        if root.is_some() {
            env.storage().persistent().extend_ttl(
                &key,
                PERSISTENT_BUMP_THRESHOLD,
                PERSISTENT_BUMP_AMOUNT,
            );
        }
        root
    }

    /// Verify a Merkle path against the root carried in `proof`.
    ///
    /// Leaves and internal nodes use SHA-256. Sibling ordering is determined
    /// by the corresponding bit of `index`; paths are limited to 32 levels.
    pub fn verify_merkle_proof(env: Env, proof: MerkleDeliveryProof) -> bool {
        Self::verify_merkle_path(&env, &proof)
    }

    /// Release a funded escrow after proving its order is included in the
    /// published delivery root for `date`.
    ///
    /// The leaf convention is `SHA-256(order_id)`. The buyer must authorize
    /// the call; a proof for a different order or an unpublished root fails.
    pub fn release_with_merkle_proof(
        env: Env,
        escrow_id: u64,
        buyer: Address,
        date: u64,
        proof: MerkleDeliveryProof,
    ) -> Result<bool, EscrowError> {
        buyer.require_auth();
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        if buyer != record.buyer {
            return Err(EscrowError::Unauthorized);
        }
        Self::validate_release_status(&record)?;

        let published_root: Option<BytesN<32>> =
            env.storage().persistent().get(&DataKey::MerkleRoot(date));
        let published_root = published_root.ok_or(EscrowError::InvalidMerkleProof)?;
        env.storage().persistent().extend_ttl(
            &DataKey::MerkleRoot(date),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        let expected_leaf: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from_array(&env, &record.order_id.to_array()))
            .into();
        if proof.root != published_root
            || proof.leaf != expected_leaf
            || !Self::verify_merkle_path(&env, &proof)
        {
            return Err(EscrowError::InvalidMerkleProof);
        }

        Self::execute_release(
            &env,
            escrow_id,
            &key,
            record.clone(),
            buyer,
            record.amount - record.released_amount - record.refunded_amount,
        )?;
        Ok(true)
    }

    fn verify_merkle_path(env: &Env, proof: &MerkleDeliveryProof) -> bool {
        if proof.proof.len() > u32::BITS {
            return false;
        }

        let mut hash = proof.leaf.clone();
        let mut index = proof.index;
        for sibling in proof.proof.iter() {
            let (left, right) = if index & 1 == 0 {
                (hash, sibling)
            } else {
                (sibling, hash)
            };
            let mut node = Bytes::new(env);
            node.append(&Bytes::from_array(env, &left.to_array()));
            node.append(&Bytes::from_array(env, &right.to_array()));
            hash = env.crypto().sha256(&node).into();
            index >>= 1;
        }

        index == 0 && hash == proof.root
    }

    /// Create an escrow in unfunded `Created` status.
    ///
    /// Optional metadata parameters (order_hash and schema) can be provided to store
    /// a hash of off-chain order details for later verification.
    ///
    /// # Errors
    /// Returns [`EscrowError::InvalidAddress`] when buyer, seller, token, or
    /// treasury are the zero address, and
    /// [`EscrowError::InvalidEscrowParticipants`] when buyer and seller are
    /// the same address.
    // Reason: Soroban ABI entry point — 9 args is part of the published
    // on-chain signature and cannot be restructured without a breaking change.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        buyer: Address,
        seller: Address,
        token: Address,
        amount: i128,
        order_id: BytesN<32>,
        timeout_ledgers: u32,
        order_hash: Option<BytesN<32>>,
        schema: Option<Symbol>,
    ) -> Result<u64, EscrowError> {
        if is_zero_address(&env, &buyer)
            || is_zero_address(&env, &seller)
            || is_zero_address(&env, &token)
        {
            return Err(EscrowError::InvalidAddress);
        }
        if buyer == seller {
            return Err(EscrowError::InvalidEscrowParticipants);
        }

        buyer.require_auth();
        Self::create_internal(
            env,
            buyer,
            seller,
            token,
            amount,
            order_id,
            timeout_ledgers,
            order_hash,
            schema,
        )
    }

    /// Shared `create` logic used by both `create` and `batch_deposit`.
    /// Callers are responsible for their own validation and
    /// `buyer.require_auth()` — batch callers authorize the buyer once for
    /// the whole batch instead of once per order, since Soroban's auth
    /// tracker only matches one invocation of `require_auth` per address per
    /// top-level call.
    // Reason: mirrors the `create` ABI signature so batch callers stay uniform.
    #[allow(clippy::too_many_arguments)]
    fn create_internal(
        env: Env,
        buyer: Address,
        seller: Address,
        token: Address,
        amount: i128,
        order_id: BytesN<32>,
        timeout_ledgers: u32,
        order_hash: Option<BytesN<32>>,
        schema: Option<Symbol>,
    ) -> Result<u64, EscrowError> {
        if let Some(pause_state) = env
            .storage()
            .instance()
            .get::<DataKey, EscrowPauseState>(&DataKey::PauseState)
        {
            if pause_state.create_paused {
                return Err(EscrowError::CreationPaused);
            }
        }

        if let Some(registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::MerchantRegistry)
        {
            let args = soroban_sdk::vec![&env, seller.to_val()];
            let status = env.try_invoke_contract::<bool, InvokeError>(
                &registry,
                &Symbol::new(&env, "is_merchant_trading"),
                args,
            );
            match status {
                Ok(Ok(true)) => {}
                Ok(Ok(false)) => return Err(EscrowError::MerchantNotTrading),
                _ => return Err(EscrowError::MerchantStatusCheckFailed),
            }
        }

        if !Self::is_token_allowed(env.clone(), token.clone()) {
            return Err(EscrowError::TokenNotWhitelisted);
        }

        if amount <= 0 {
            return Err(EscrowError::InvalidAmount);
        }
        let limits: EscrowAmountLimits = Self::get_limits(env.clone())?;
        if amount < limits.min_amount {
            return Err(EscrowError::AmountBelowMin);
        }
        if amount > limits.max_amount {
            return Err(EscrowError::AmountAboveMax);
        }

        // Metadata must be supplied fully (both order_hash and schema) or not
        // at all. A half-set entry would otherwise be persisted with the set
        // half and stale/absent other half, silently dropping metadata — reject
        // it loudly with a typed error instead (issue #38). This shared path is
        // used by `create`, `deposit`, and every `batch_deposit` entry, so all
        // three behave identically.
        if order_hash.is_some() != schema.is_some() {
            return Err(EscrowError::InvalidMetadata);
        }

        let mut last_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::LastEscrowId)
            .unwrap_or(0);
        last_id += 1;
        env.storage()
            .instance()
            .set(&DataKey::LastEscrowId, &last_id);

        let timeout_ledger = timeout_ledgers
            .checked_add(env.ledger().sequence())
            .ok_or(EscrowError::InvalidExtension)?;
        let record = EscrowRecord {
            escrow_id: last_id,
            buyer: buyer.clone(),
            seller: seller.clone(),
            token: token.clone(),
            amount,
            released_amount: 0,
            refunded_amount: 0,
            status: EscrowStatus::Created,
            order_id: order_id.clone(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            timeout_ledger,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(last_id), &record);

        // Maintain global escrow ID index for list_escrows (issue #49).
        let mut all_ids: soroban_sdk::Vec<u64> = env
            .storage()
            .instance()
            .get(&DataKey::EscrowIds)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        all_ids.push_back(last_id);
        env.storage().instance().set(&DataKey::EscrowIds, &all_ids);

        // Keep each buyer index entry separate so no persistent value grows
        // with the buyer's lifetime escrow count.
        let buyer_count_key = DataKey::BuyerEscrowCount(buyer.clone());
        let buyer_count: u32 = env
            .storage()
            .persistent()
            .get(&buyer_count_key)
            .unwrap_or(0);
        let next_buyer_count = buyer_count
            .checked_add(1)
            .ok_or(EscrowError::InvalidExtension)?;
        env.storage().persistent().set(
            &DataKey::BuyerEscrowAt(buyer.clone(), buyer_count),
            &last_id,
        );
        env.storage()
            .persistent()
            .set(&buyer_count_key, &next_buyer_count);

        // Persist each metadata half independently so a later call can supply
        // the missing one (issue #181). Both halves are only ever stored
        // together here: `order_hash`/`schema` are validated to be
        // all-or-nothing, so a half-set entry can never silently drop metadata
        // (issue #38). Borrow here; the combined match below moves the
        // originals into the event.
        if let Some(hash) = &order_hash {
            env.storage()
                .persistent()
                .set(&DataKey::EscrowMetadataHash(last_id), hash);
        }
        if let Some(sch) = &schema {
            env.storage()
                .persistent()
                .set(&DataKey::EscrowMetadataSchema(last_id), sch);
        }

        // The metadata event is only emitted once both halves are present. The
        // order id is carried as a topic so indexers can filter by escrow
        // without deserializing the event body (issue #142).
        if let (Some(hash), Some(sch)) = (order_hash, schema) {
            env.events().publish(
                (
                    symbol_short!("escrow"),
                    symbol_short!("metadata"),
                    order_id.clone(),
                ),
                EscrowMetadataEvent {
                    escrow_id: order_id.clone(),
                    order_hash: hash,
                    schema: sch,
                },
            );
        }

        // A long-lived, open escrow must not be evicted while it is still
        // being read: bump the TTL of the record, its buyer index, and the
        // contract instance (mirrors marketplace/reputation).
        let storage = env.storage().persistent();
        storage.extend_ttl(
            &DataKey::Escrow(last_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(
            &buyer_count_key,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("created"), last_id),
            EscrowCreatedEvent {
                escrow_id: last_id,
                buyer: record.buyer.clone(),
                seller: record.seller.clone(),
                token: record.token.clone(),
                amount: record.amount,
                order_id,
                timeout_ledger,
            },
        );

        Ok(last_id)
    }

    /// Fund an existing escrow that is in `Created` status.
    pub fn fund(env: Env, escrow_id: u64, buyer: Address) -> Result<bool, EscrowError> {
        buyer.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if buyer != record.buyer {
            return Err(EscrowError::Unauthorized);
        }

        if record.status == EscrowStatus::Funded {
            return Err(EscrowError::AlreadyFunded);
        }

        if record.status == EscrowStatus::Cancelled {
            return Err(EscrowError::AlreadyCancelled);
        }

        if record.status != EscrowStatus::Created {
            return Err(EscrowError::InvalidStatus);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        token_client.transfer(&buyer, &env.current_contract_address(), &record.amount);

        record.status = EscrowStatus::Funded;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        Ok(true)
    }

    /// Cancel an escrow that has been created but not yet funded.
    /// Only the merchant (seller) may call.
    pub fn cancel(
        env: Env,
        escrow_id: u64,
        caller: Address,
        reason: Symbol,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if caller != record.seller {
            return Err(EscrowError::Unauthorized);
        }

        if record.status == EscrowStatus::Funded {
            return Err(EscrowError::AlreadyFunded);
        }

        if record.status == EscrowStatus::Cancelled {
            return Err(EscrowError::AlreadyCancelled);
        }

        if record.status != EscrowStatus::Created {
            return Err(EscrowError::InvalidStatus);
        }

        record.status = EscrowStatus::Cancelled;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("cancelled"),
                record.order_id.clone(),
            ),
            EscrowCancelledEvent {
                escrow_id: record.order_id.clone(),
                cancelled_by: caller,
                reason,
            },
        );

        Ok(true)
    }

    /// Deposit funds into escrow for an order.
    /// Combined convenience call: creates an escrow and immediately funds it.
    // Reason: Soroban ABI entry point — 9 args is part of the published
    // on-chain signature and cannot be restructured without a breaking change.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        env: Env,
        buyer: Address,
        seller: Address,
        token: Address,
        amount: i128,
        order_id: BytesN<32>,
        timeout_ledgers: u32,
        order_hash: Option<BytesN<32>>,
        schema: Option<Symbol>,
    ) -> Result<u64, EscrowError> {
        if is_zero_address(&env, &buyer)
            || is_zero_address(&env, &seller)
            || is_zero_address(&env, &token)
        {
            return Err(EscrowError::InvalidAddress);
        }
        if buyer == seller {
            return Err(EscrowError::InvalidEscrowParticipants);
        }

        buyer.require_auth();
        Self::deposit_internal(
            env,
            buyer,
            seller,
            token,
            amount,
            order_id,
            timeout_ledgers,
            order_hash,
            schema,
        )
    }

    /// Shared `deposit` logic used by both `deposit` and `batch_deposit`.
    /// Callers are responsible for their own validation and
    /// `buyer.require_auth()`.
    // Reason: mirrors the `deposit` ABI signature so batch callers stay uniform.
    #[allow(clippy::too_many_arguments)]
    fn deposit_internal(
        env: Env,
        buyer: Address,
        seller: Address,
        token: Address,
        amount: i128,
        order_id: BytesN<32>,
        timeout_ledgers: u32,
        order_hash: Option<BytesN<32>>,
        schema: Option<Symbol>,
    ) -> Result<u64, EscrowError> {
        let escrow_id = Self::create_internal(
            env.clone(),
            buyer.clone(),
            seller,
            token.clone(),
            amount,
            order_id,
            timeout_ledgers,
            order_hash,
            schema,
        )?;

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&buyer, &env.current_contract_address(), &amount);

        record.status = EscrowStatus::Funded;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);

        Ok(escrow_id)
    }

    /// Deposit multiple orders for a single buyer into escrow in one call
    /// (issue #317). Reduces the per-order transaction overhead of calling
    /// `deposit` separately for each order.
    ///
    /// The buyer authorizes the whole batch once; each order may specify a
    /// different seller, token, and amount. Because a Soroban contract
    /// invocation is atomic, an error on any entry aborts the whole call —
    /// every escrow created earlier in the batch is rolled back along with
    /// it, so callers never observe a partial batch. Each successfully
    /// created escrow still emits its own `EscrowCreatedEvent` (and
    /// `EscrowMetadataEvent` when metadata is supplied), exactly as a
    /// standalone `deposit` call would.
    pub fn batch_deposit(
        env: Env,
        buyer: Address,
        orders: Vec<BatchDepositParams>,
    ) -> Result<Vec<u64>, EscrowError> {
        if is_zero_address(&env, &buyer) {
            return Err(EscrowError::InvalidAddress);
        }
        buyer.require_auth();

        let mut escrow_ids = Vec::new(&env);
        for order in orders.iter() {
            if is_zero_address(&env, &order.seller) || is_zero_address(&env, &order.token) {
                return Err(EscrowError::InvalidAddress);
            }
            if buyer == order.seller {
                return Err(EscrowError::InvalidEscrowParticipants);
            }
            let escrow_id = Self::deposit_internal(
                env.clone(),
                buyer.clone(),
                order.seller,
                order.token,
                order.amount,
                order.order_id,
                order.timeout_ledgers,
                order.order_hash,
                order.schema,
            )?;
            escrow_ids.push_back(escrow_id);
        }
        Ok(escrow_ids)
    }

    /// Atomically create and fund multiple escrows for one buyer.
    ///
    /// The buyer approves this contract to spend the aggregate amount for
    /// each token. Each token is pulled once with `transfer_from`, reducing
    /// repeated transfer overhead. Any invalid item or failed allowance
    /// reverts the complete batch. Timeouts in `items` are absolute ledger
    /// sequence numbers.
    pub fn batch_create_escrows(
        env: Env,
        buyer: Address,
        items: Vec<BatchEscrowItem>,
    ) -> Result<Vec<u64>, EscrowError> {
        if is_zero_address(&env, &buyer) {
            return Err(EscrowError::InvalidAddress);
        }
        if items.len() > MAX_PAGE_LIMIT {
            return Err(EscrowError::BatchLimitExceeded);
        }
        buyer.require_auth();

        let current_ledger = env.ledger().sequence();
        let mut token_totals: Map<Address, i128> = Map::new(&env);
        for item in items.iter() {
            if is_zero_address(&env, &item.seller) || is_zero_address(&env, &item.token) {
                return Err(EscrowError::InvalidAddress);
            }
            if buyer == item.seller {
                return Err(EscrowError::InvalidEscrowParticipants);
            }
            item.timeout_ledger
                .checked_sub(current_ledger)
                .ok_or(EscrowError::InvalidExtension)?;
            if item.amount <= 0 {
                return Err(EscrowError::InvalidAmount);
            }
            let aggregate = token_totals.get(item.token.clone()).unwrap_or(0i128);
            token_totals.set(
                item.token,
                aggregate
                    .checked_add(item.amount)
                    .ok_or(EscrowError::InvalidAmount)?,
            );
        }

        let mut escrow_ids = Vec::new(&env);
        for item in items.iter() {
            let timeout_ledgers = item
                .timeout_ledger
                .checked_sub(current_ledger)
                .ok_or(EscrowError::InvalidExtension)?;
            let escrow_id = Self::create_internal(
                env.clone(),
                buyer.clone(),
                item.seller,
                item.token,
                item.amount,
                item.order_id,
                timeout_ledgers,
                None,
                None,
            )?;
            let key = DataKey::Escrow(escrow_id);
            let mut record: EscrowRecord = env
                .storage()
                .persistent()
                .get(&key)
                .ok_or(EscrowError::NotFound)?;
            record.status = EscrowStatus::Funded;
            record.updated_at = env.ledger().timestamp();
            env.storage().persistent().set(&key, &record);
            env.storage().persistent().extend_ttl(
                &key,
                PERSISTENT_BUMP_THRESHOLD,
                PERSISTENT_BUMP_AMOUNT,
            );
            escrow_ids.push_back(escrow_id);
        }

        let contract_address = env.current_contract_address();
        for (token, amount) in token_totals.iter() {
            let token_client = soroban_sdk::token::Client::new(&env, &token);
            token_client.transfer_from(
                &contract_address,
                &buyer,
                &contract_address,
                &amount,
            );
        }
        Ok(escrow_ids)
    }

    /// Release funds for multiple escrows in a single call (issue #317).
    ///
    /// Each entry is released exactly as `partial_release` would (buyer or
    /// admin only), in order. An error on any entry aborts and reverts the
    /// entire batch. Each release still emits its own `EscrowReleasedEvent`.
    pub fn batch_release(
        env: Env,
        caller: Address,
        releases: Vec<BatchReleaseParams>,
    ) -> Result<Vec<PartialReleaseResult>, EscrowError> {
        caller.require_auth();

        let mut results = Vec::new(&env);
        for item in releases.iter() {
            let result = Self::partial_release_internal(
                env.clone(),
                item.escrow_id,
                caller.clone(),
                item.release_amount,
            )?;
            results.push_back(result);
        }
        Ok(results)
    }

    /// Refund funds for multiple escrows in a single call (issue #317).
    ///
    /// Each entry is refunded exactly as `partial_refund` would (seller/admin
    /// any time, buyer after timeout), in order. An error on any entry aborts
    /// and reverts the entire batch. Each refund still emits its own
    /// `EscrowRefundedEvent`.
    pub fn batch_refund(
        env: Env,
        caller: Address,
        refunds: Vec<BatchRefundParams>,
    ) -> Result<Vec<PartialRefundResult>, EscrowError> {
        caller.require_auth();

        let mut results = Vec::new(&env);
        for item in refunds.iter() {
            let result = Self::partial_refund_internal(
                env.clone(),
                item.escrow_id,
                caller.clone(),
                item.refund_amount,
            )?;
            results.push_back(result);
        }
        Ok(results)
    }

    /// Release a partial amount to the seller.
    /// `release_amount` must not exceed the balance after prior releases and refunds.
    /// If release_amount equals the remaining balance, set status to Released.
    /// The platform fee is deducted from `release_amount` (issue #27).
    pub fn partial_release(
        env: Env,
        escrow_id: u64,
        caller: Address,
        release_amount: i128,
    ) -> Result<PartialReleaseResult, EscrowError> {
        caller.require_auth();
        Self::partial_release_internal(env, escrow_id, caller, release_amount)
    }

    /// Shared `partial_release` logic used by both `partial_release` and
    /// `batch_release`. Callers are responsible for their own
    /// `caller.require_auth()`.
    fn partial_release_internal(
        env: Env,
        escrow_id: u64,
        caller: Address,
        release_amount: i128,
    ) -> Result<PartialReleaseResult, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if caller != record.buyer && !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        check_not_terminal(&record)?;

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }
        Self::validate_release_status(&record)?;

        if record.amount > DUAL_CONTROL_THRESHOLD {
            return Err(EscrowError::SignedProofRequired);
        }

        // When the admin has required it, buyer-originated releases must pass
        // the release-eligibility gate (issue #48). Admins are not gated.
        if caller == record.buyer
            && env
                .storage()
                .persistent()
                .get(&DataKey::RequireReleaseCondition(escrow_id))
                .unwrap_or(false)
            && Self::release_block_reason(env.clone(), &record).is_some()
        {
            return Err(EscrowError::ConditionNotMet);
        }

        Self::execute_release(&env, escrow_id, &key, record, caller, release_amount)
    }

    /// Shared release logic used by both `partial_release` and
    /// `evaluate_and_release`. Callers are responsible for their own
    /// authorization checks before invoking this.
    ///
    /// The platform fee (per `FeeConfig` or the multi-treasury
    /// `FeeDistribution`) is deducted from `release_amount` and transferred to
    /// the treasury(ies); the seller receives the remainder (issue #27).
    /// `released_amount` tracks the full escrow-amount released, not the net
    /// seller payout.
    fn execute_release(
        env: &Env,
        escrow_id: u64,
        key: &DataKey,
        mut record: EscrowRecord,
        caller: Address,
        release_amount: i128,
    ) -> Result<PartialReleaseResult, EscrowError> {
        if release_amount <= 0 {
            return Err(EscrowError::ZeroAmount);
        }

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        if release_amount > remaining {
            return Err(EscrowError::InsufficientEscrowBalance);
        }

        let token_client = soroban_sdk::token::Client::new(env, &record.token);

        let payout = Self::compute_payout(env, release_amount)?;
        Self::distribute_fee(env, &token_client, payout.fee)?;
        token_client.transfer(
            &env.current_contract_address(),
            &record.seller,
            &payout.seller_net,
        );

        record.released_amount += release_amount;
        let new_remaining = record.amount - record.released_amount - record.refunded_amount;
        let fully_released = new_remaining == 0;
        if fully_released {
            record.status = EscrowStatus::Released;
        }

        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("released"),
                escrow_id,
            ),
            EscrowReleasedEvent {
                escrow_id,
                seller: record.seller.clone(),
                amount: release_amount,
                released_by: caller,
            },
        );

        if fully_released {
            let yield_config: Option<YieldConfig> = env
                .storage()
                .persistent()
                .get(&DataKey::EscrowYieldConfig(escrow_id));
            if let Some(cfg) = &yield_config {
                let (yield_amount, held_seconds) = Self::compute_yield(&record, Some(cfg), env);
                env.events().publish(
                    (symbol_short!("escrow"), symbol_short!("yield"), escrow_id),
                    EscrowYieldAccruedEvent {
                        escrow_id,
                        seller: record.seller.clone(),
                        yield_amount,
                        held_seconds,
                    },
                );
            }
        }

        Ok(PartialReleaseResult {
            released: release_amount,
            remaining: new_remaining,
            fully_released,
        })
    }

    /// Release escrowed funds to the seller. Only the buyer or admin may call.
    /// The platform fee is deducted from the released amount (issue #27).
    pub fn release(
        env: Env,
        escrow_id: u64,
        caller: Address,
        recipient: Address,
    ) -> Result<bool, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if recipient != record.seller {
            return Err(EscrowError::InvalidReleaseRecipient);
        }

        // Validate seller's merchant category if authorization is configured
        Self::validate_seller_category(&env, &record.seller)?;

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        Self::partial_release(env, escrow_id, caller, remaining)?;
        Ok(true)
    }

    /// Refund escrowed funds to the buyer.
    /// Seller or admin may refund at any time; the buyer may refund after timeout.
    /// Refunds the full remaining (unreleased, unrefunded) balance.
    pub fn refund(env: Env, escrow_id: u64, caller: Address) -> Result<bool, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        Self::partial_refund(env, escrow_id, caller, remaining)?;
        Ok(true)
    }

    /// Refund a partial amount to the buyer.
    /// `refund_amount` must be <= (record.amount - record.released_amount - record.refunded_amount).
    /// Status remains `Funded` unless the refund exhausts the remaining balance, in
    /// which case status becomes `Refunded`.
    /// Seller or admin may refund at any time; the buyer may refund after timeout.
    pub fn partial_refund(
        env: Env,
        escrow_id: u64,
        caller: Address,
        refund_amount: i128,
    ) -> Result<PartialRefundResult, EscrowError> {
        caller.require_auth();
        Self::partial_refund_internal(env, escrow_id, caller, refund_amount)
    }

    /// Shared `partial_refund` logic used by both `partial_refund` and
    /// `batch_refund`. Callers are responsible for their own
    /// `caller.require_auth()`.
    fn partial_refund_internal(
        env: Env,
        escrow_id: u64,
        caller: Address,
        refund_amount: i128,
    ) -> Result<PartialRefundResult, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        check_not_terminal(&record)?;

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        let timeout_reached = env.ledger().sequence() >= record.timeout_ledger;

        // Check for shipment proof - required for seller to claim on timeout
        let has_proof = env
            .storage()
            .persistent()
            .has(&DataKey::ShipmentProof(escrow_id));

        if caller == record.seller || Self::is_admin(env.clone(), caller.clone()) {
            // Seller or admin: allowed at any time while funded,
            // BUT on timeout without proof, seller cannot claim (buyer has exclusive refund rights)
            if timeout_reached && !has_proof {
                return Err(EscrowError::TimeoutNotReached);
            }
        } else if caller == record.buyer {
            // Buyer: can always refund after timeout, even without shipment proof
            if !timeout_reached {
                return Err(EscrowError::TimeoutNotReached);
            }
        } else {
            return Err(EscrowError::Unauthorized);
        }

        if refund_amount <= 0 {
            return Err(EscrowError::ZeroAmount);
        }

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        if refund_amount > remaining {
            return Err(EscrowError::InsufficientEscrowBalance);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        token_client.transfer(
            &env.current_contract_address(),
            &record.buyer,
            &refund_amount,
        );

        record.refunded_amount += refund_amount;
        let new_remaining = record.amount - record.released_amount - record.refunded_amount;
        let fully_refunded = new_remaining == 0;
        if fully_refunded {
            record.status = EscrowStatus::Refunded;
        }

        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("refunded"),
                escrow_id,
            ),
            EscrowRefundedEvent {
                escrow_id,
                buyer: record.buyer.clone(),
                amount: refund_amount,
                remaining: new_remaining,
                refunded_by: caller,
            },
        );

        Ok(PartialRefundResult {
            refunded: refund_amount,
            remaining: new_remaining,
            fully_refunded,
        })
    }

    /// Configure a conditional release for an escrow, gated on an external oracle
    /// contract (issue #339). Callable by the buyer, seller, or admin while the
    /// escrow is not in a terminal state.
    ///
    /// `oracle_contract` must implement `resolve(condition_type: Symbol) -> bool`.
    /// `evaluate_and_release` calls this function and releases funds to the
    /// seller only when it returns `true`.
    pub fn set_release_condition(
        env: Env,
        caller: Address,
        escrow_id: u64,
        condition_type: Symbol,
        oracle_contract: Address,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if caller != record.buyer
            && caller != record.seller
            && !Self::is_admin(env.clone(), caller.clone())
        {
            return Err(EscrowError::Unauthorized);
        }

        check_not_terminal(&record)?;

        env.storage().persistent().set(
            &DataKey::ReleaseCondition(escrow_id),
            &ReleaseCondition {
                condition_type: condition_type.clone(),
                oracle_contract: oracle_contract.clone(),
            },
        );

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("condset"), escrow_id),
            ReleaseConditionSetEvent {
                escrow_id,
                condition_type,
                oracle_contract,
            },
        );

        Ok(true)
    }

    /// Read-only getter for the release condition configured on an escrow.
    pub fn get_release_condition(
        env: Env,
        escrow_id: u64,
    ) -> Result<ReleaseCondition, EscrowError> {
        env.storage()
            .persistent()
            .get(&DataKey::ReleaseCondition(escrow_id))
            .ok_or(EscrowError::ReleaseConditionNotSet)
    }

    /// Deprecated insecure bool-oracle release path. It remains in the ABI for
    /// compatibility but never releases funds; use
    /// `verify_delivery_and_release` with an oracle signature instead.
    pub fn evaluate_and_release(
        env: Env,
        _escrow_id: u64,
        caller: Address,
    ) -> Result<PartialReleaseResult, EscrowError> {
        caller.require_auth();
        Err(EscrowError::SignedProofRequired)
    }

    /// Verify an oracle-signed delivery attestation and release the escrow's
    /// full remaining balance to its seller.
    ///
    /// The signed payload consists of the XDR encoding of `escrow_id`,
    /// `carrier_code`, `tracking_hash`, and `delivery_timestamp`. The proof's
    /// public key must equal the admin-configured key, and the delivery time
    /// must fall between escrow creation and the current ledger timestamp.
    pub fn verify_delivery_and_release(
        env: Env,
        escrow_id: u64,
        caller: Address,
        proof: SignedDeliveryProof,
    ) -> Result<PartialReleaseResult, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };
        check_not_terminal(&record)?;
        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        if record.amount > DUAL_CONTROL_THRESHOLD {
            let config: DualControlConfig = env
                .storage()
                .persistent()
                .get(&DataKey::DualControlConfig(escrow_id))
                .ok_or(EscrowError::DualControlNotConfigured)?;
            if !config.is_secondary_approved {
                return Err(EscrowError::SecondaryApprovalRequired);
            }
        }

        let configured_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::OraclePublicKey)
            .ok_or(EscrowError::OraclePublicKeyNotSet)?;
        if proof.escrow_id != escrow_id
            || proof.oracle_pubkey != configured_key
            || proof.delivery_timestamp < record.created_at
            || proof.delivery_timestamp > env.ledger().timestamp()
        {
            return Err(EscrowError::InvalidSignedDeliveryProof);
        }

        use soroban_sdk::xdr::ToXdr;
        let payload = SignedDeliveryPayload {
            escrow_id: proof.escrow_id,
            carrier_code: proof.carrier_code,
            tracking_hash: proof.tracking_hash,
            delivery_timestamp: proof.delivery_timestamp,
        }
        .to_xdr(&env);
        env.crypto()
            .ed25519_verify(&configured_key, &payload, &proof.signature);

        let remaining = record.amount - record.released_amount - record.refunded_amount;
        Self::execute_release(&env, escrow_id, &key, record, caller, remaining)
    }

    /// Mark the escrow as disputed. Only the buyer or seller may call.
    pub fn dispute(env: Env, escrow_id: u64, caller: Address) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if caller != record.buyer && caller != record.seller {
            return Err(EscrowError::Unauthorized);
        }

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        record.status = EscrowStatus::Disputed;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("disputed"),
                escrow_id,
            ),
            EscrowDisputedEvent {
                escrow_id,
                disputed_by: caller,
            },
        );

        Ok(true)
    }

    /// Resolve a disputed escrow. Only the admin may call.
    pub fn resolve_dispute(
        env: Env,
        escrow_id: u64,
        caller: Address,
        release_to_seller: bool,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        if !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if record.status != EscrowStatus::Disputed {
            return Err(EscrowError::NotDisputed);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        if release_to_seller {
            let payout = Self::compute_payout(&env, record.amount)?;
            Self::distribute_fee(&env, &token_client, payout.fee)?;
            token_client.transfer(
                &env.current_contract_address(),
                &record.seller,
                &payout.seller_net,
            );
            record.status = EscrowStatus::Released;
        } else {
            token_client.transfer(
                &env.current_contract_address(),
                &record.buyer,
                &record.amount,
            );
            record.status = EscrowStatus::Refunded;
        }

        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("resolved"),
                escrow_id,
            ),
            EscrowResolvedEvent {
                escrow_id,
                release_to_seller,
                resolved_by: caller,
            },
        );

        Ok(true)
    }

    /// Resolve a disputed escrow with an exact buyer, seller, and mediator split.
    ///
    /// Only the admin may call. The award amounts must all be non-negative
    /// and sum exactly to the escrow amount. This resolution bypasses the
    /// ordinary release fee because the mediator fee is explicit in the award.
    pub fn resolve_dispute_split(
        env: Env,
        escrow_id: u64,
        caller: Address,
        award: DisputeResolutionAward,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        if record.status != EscrowStatus::Disputed {
            return Err(EscrowError::NotDisputed);
        }
        if record.released_amount != 0 || record.refunded_amount != 0 {
            return Err(EscrowError::InvalidDisputeAward);
        }
        if award.buyer_amount < 0 || award.seller_amount < 0 || award.mediator_fee < 0 {
            return Err(EscrowError::InvalidDisputeAward);
        }
        let total_award = award
            .buyer_amount
            .checked_add(award.seller_amount)
            .and_then(|total| total.checked_add(award.mediator_fee))
            .ok_or(EscrowError::InvalidDisputeAward)?;
        if total_award != record.amount
            || (award.mediator_fee > 0 && is_zero_address(&env, &award.mediator_address))
        {
            return Err(EscrowError::InvalidDisputeAward);
        }
        let seller_and_mediator = award
            .seller_amount
            .checked_add(award.mediator_fee)
            .ok_or(EscrowError::InvalidDisputeAward)?;

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);
        let contract_address = env.current_contract_address();
        if award.buyer_amount > 0 {
            token_client.transfer(&contract_address, &record.buyer, &award.buyer_amount);
        }
        if award.seller_amount > 0 {
            token_client.transfer(&contract_address, &record.seller, &award.seller_amount);
        }
        if award.mediator_fee > 0 {
            token_client.transfer(
                &contract_address,
                &award.mediator_address,
                &award.mediator_fee,
            );
        }

        record.refunded_amount = award.buyer_amount;
        record.released_amount = seller_and_mediator;
        record.status = if seller_and_mediator == 0 {
            EscrowStatus::Refunded
        } else {
            EscrowStatus::Released
        };
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("dispsplit"),
                escrow_id,
            ),
            DisputeResolvedEvent {
                escrow_id,
                buyer_amount: award.buyer_amount,
                seller_amount: award.seller_amount,
                mediator_fee: award.mediator_fee,
                mediator_address: award.mediator_address,
                resolved_by: caller,
            },
        );
        Ok(true)
    }

    /// Read-only helper for settlement workers to determine whether release can proceed.
    ///
    /// Reason symbols (≤9 chars for `symbol_short!` compat):
    ///   `ok`       — escrow is funded and not timed out
    ///   `notfound` — escrow record does not exist
    ///   `released` — already released (terminal)
    ///   `refunded` — already refunded (terminal)
    ///   `disputed` — escrow is under dispute
    ///   `timeout`  — refund timeout has been reached
    pub fn get_release_eligibility(env: Env, escrow_id: u64) -> ReleaseEligibility {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => {
                return ReleaseEligibility {
                    escrow_id: BytesN::from_array(&env, &[0u8; 32]),
                    eligible: false,
                    reason: symbol_short!("notfound"),
                };
            }
        };

        let reason = match Self::release_block_reason(env, &record) {
            Some(reason) => reason,
            None => symbol_short!("ok"),
        };

        ReleaseEligibility {
            escrow_id: record.order_id,
            eligible: reason == symbol_short!("ok"),
            reason,
        }
    }

    /// Read-only getter for escrow state.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_escrow(env: Env, escrow_id: u64) -> Result<EscrowRecord, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        // Reads extend the TTL so a long-lived, open escrow is not evicted
        // while it is still being read (mirrors marketplace `get_merchant`).
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        Ok(record)
    }

    /// Read-only buyer-facing receipt for an escrow.
    ///
    /// Returns a compact [`EscrowReceipt`] containing the identifiers and
    /// current status that a backend service can forward to the buyer after
    /// escrow creation or as a status check.  The full record (amount, token,
    /// timeout, …) is available via [`get_escrow`].
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_receipt(env: Env, escrow_id: u64) -> Result<EscrowReceipt, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        Ok(EscrowReceipt {
            escrow_id: record.escrow_id,
            buyer: record.buyer,
            seller: record.seller,
            order_id: record.order_id,
            status: record.status,
        })
    }

    /// Read-only merchant-facing receipt for dashboards and settlement checks.
    ///
    /// Returns a [`MerchantEscrowReceipt`] with the order id as `escrow_id`,
    /// the seller as `merchant`, and a computed `release_eligible` flag that
    /// does not mutate contract state.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_merchant_receipt(
        env: Env,
        escrow_id: u64,
    ) -> Result<MerchantEscrowReceipt, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        let release_eligible = Self::release_block_reason(env, &record).is_none();
        Ok(MerchantEscrowReceipt {
            escrow_id: record.order_id,
            merchant: record.seller,
            buyer: record.buyer,
            status: record.status,
            release_eligible,
        })
    }

    /// Read-only complete state snapshot of an escrow (issue #329).
    ///
    /// Aggregates the full escrow record, the fee configuration applied to
    /// it, and computed fields (current timeout status and release
    /// eligibility) in a single call, so off-chain indexers and auditors
    /// don't have to replay contract events to reconstruct current state.
    /// Never mutates storage.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_escrow_snapshot(env: Env, escrow_id: u64) -> Result<EscrowSnapshot, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;

        let fee_config: FeeConfig = Self::get_fee_config(env.clone())?;
        let current_ledger = env.ledger().sequence();
        let timed_out =
            record.status == EscrowStatus::Funded && current_ledger >= record.timeout_ledger;
        let release_eligible = Self::release_block_reason(env.clone(), &record).is_none();

        Ok(EscrowSnapshot {
            record,
            fee_config,
            current_ledger,
            timed_out,
            release_eligible,
        })
    }

    /// Configure optional yield accrual for an escrow (issue #331). Admin-only.
    ///
    /// `apr_bps` is the annual yield rate in basis points (max 10000 = 100%).
    /// Yield is prorated by the actual time the escrow is held and reported
    /// via [`EscrowYieldAccruedEvent`] when the escrow is fully released.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if `admin` is not an escrow admin.
    /// - [`EscrowError::InvalidYieldConfig`] if `apr_bps` exceeds 10000.
    /// - [`EscrowError::NotFound`] if `escrow_id` does not exist.
    /// - Any terminal-state error from [`check_not_terminal`] once the
    ///   escrow has already been released, refunded, or cancelled.
    pub fn set_yield_config(
        env: Env,
        admin: Address,
        escrow_id: u64,
        lending_contract: Address,
        apr_bps: u32,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        if apr_bps > 10_000 {
            return Err(EscrowError::InvalidYieldConfig);
        }

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        check_not_terminal(&record)?;

        env.storage().persistent().set(
            &DataKey::EscrowYieldConfig(escrow_id),
            &YieldConfig {
                lending_contract,
                apr_bps,
            },
        );

        Ok(true)
    }

    /// Monotonic yield snapshot for an escrow (issue #34).
    ///
    /// Returns a [`YieldView`] containing every input needed to compute
    /// display-relevant yield numbers.  `snapshot_ledger` anchors the read
    /// to the current ledger, `held_seconds` is derived from
    /// `created_at` to the snapshot ledger's close time, and `accrued` is
    /// the yield at that frozen point.  Two calls within the same ledger
    /// always return identical results; calls in different ledgers produce
    /// monotonically increasing `held_seconds` and `accrued`.
    ///
    /// Returns zero yield fields when no `YieldConfig` is set.
    /// Never mutates storage.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_accrued_yield(env: Env, escrow_id: u64) -> Result<YieldView, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;

        let yield_config: Option<YieldConfig> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowYieldConfig(escrow_id));
        let apy_bps = yield_config.as_ref().map(|c| c.apr_bps).unwrap_or(0);
        let snapshot_ledger = env.ledger().sequence();
        let (accrued, held_seconds) = Self::compute_yield(&record, yield_config.as_ref(), &env);

        let remaining = record.amount - record.released_amount - record.refunded_amount;

        Ok(YieldView {
            escrow_id,
            principal: remaining,
            apy_bps,
            held_seconds,
            accrued,
            snapshot_ledger,
        })
    }

    /// Read-only compact escrow summary for API/indexer consumers (issue #90).
    ///
    /// Returns all display fields needed by the backend event indexer in a
    /// single call. The response is stable for both terminal and non-terminal
    /// escrows. Never mutates storage.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_escrow_summary(env: Env, escrow_id: u64) -> Result<EscrowSummary, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;

        Ok(EscrowSummary {
            escrow_id: record.order_id,
            buyer: record.buyer,
            merchant: record.seller,
            amount: record.amount,
            status: record.status,
        })
    }

    /// Propose a new primary admin. Must be called by current primary admin.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<bool, EscrowError> {
        current_admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if current_admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("proposed")),
            AdminProposedEvent {
                current_admin,
                new_admin,
            },
        );
        Ok(true)
    }

    /// Accept the primary admin role. Must be called by the proposed new admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<bool, EscrowError> {
        new_admin.require_auth();
        let pending_admin: Address = match env.storage().instance().get(&DataKey::PendingAdmin) {
            Some(addr) => addr,
            None => return Err(EscrowError::NoPendingTransfer),
        };
        if new_admin != pending_admin {
            return Err(EscrowError::InvalidPendingAdmin);
        }

        let mut admin_list: soroban_sdk::Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if let Some(index) = admin_list.first_index_of(&new_admin) {
            admin_list.remove(index);
            env.storage()
                .instance()
                .set(&DataKey::AdminList, &admin_list);
        }

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("accepted")),
            AdminAcceptedEvent { new_admin },
        );
        Ok(true)
    }

    /// Cancel a pending admin transfer. Must be called by current primary admin.
    pub fn cancel_admin_transfer(env: Env, current_admin: Address) -> Result<bool, EscrowError> {
        current_admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if current_admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }
        if !env.storage().instance().has(&DataKey::PendingAdmin) {
            return Err(EscrowError::NoPendingTransfer);
        }
        env.storage().instance().remove(&DataKey::PendingAdmin);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("cancelled")),
            AdminTransferCancelledEvent { current_admin },
        );
        Ok(true)
    }

    /// Add a co-admin. Must be called by the primary admin.
    pub fn add_co_admin(
        env: Env,
        admin: Address,
        new_co_admin: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }
        if new_co_admin == primary_admin {
            return Err(EscrowError::AdminAlreadyExists);
        }
        let mut admin_list: soroban_sdk::Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if admin_list.contains(&new_co_admin) {
            return Err(EscrowError::AdminAlreadyExists);
        }
        admin_list.push_back(new_co_admin);
        env.storage()
            .instance()
            .set(&DataKey::AdminList, &admin_list);
        Ok(true)
    }

    /// Prune dispute and timeout votes for settled/terminal escrows (`Released`, `Refunded`, `Cancelled`, `ResolvedSeller`, `ResolvedBuyer`).
    ///
    /// Callable by admin in bounded batches (`escrow_ids.len() <= MAX_PAGE_LIMIT`).
    /// Returns the number of escrows whose auxiliary dispute data was pruned from persistent storage.
    pub fn prune_dispute_votes(
        env: Env,
        admin: Address,
        escrow_ids: soroban_sdk::Vec<u64>,
    ) -> Result<u32, EscrowError> {
        admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }

        if escrow_ids.len() > MAX_PAGE_LIMIT {
            return Err(EscrowError::InvalidLimits);
        }

        let mut pruned_count: u32 = 0;

        for id in escrow_ids.iter() {
            let key = DataKey::Escrow(id);
            if let Some(record) = env.storage().persistent().get::<_, EscrowRecord>(&key) {
                let is_terminal = EscrowTerminalState::from_status(&record.status).is_some();

                if is_terminal {
                    let votes_key = DataKey::DisputeVotes(id);
                    let ext_key = DataKey::TimeoutExtensionVotes(id);
                    let mut had_data = false;
                    if env.storage().persistent().has(&votes_key) {
                        env.storage().persistent().remove(&votes_key);
                        had_data = true;
                    }
                    if env.storage().persistent().has(&ext_key) {
                        env.storage().persistent().remove(&ext_key);
                        had_data = true;
                    }
                    if had_data {
                        pruned_count += 1;
                    }
                }
            }
        }

        if pruned_count > 0 {
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("pruned")),
                DisputeVotesPrunedEvent {
                    pruned_count,
                    pruned_by: admin,
                },
            );
        }

        Ok(pruned_count)
    }

    /// Remove a co-admin. Must be called by the primary admin.
    pub fn remove_co_admin(
        env: Env,
        admin: Address,
        co_admin: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        let primary_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(EscrowError::NotFound)?;
        if admin != primary_admin {
            return Err(EscrowError::Unauthorized);
        }
        let mut admin_list: soroban_sdk::Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        let index = match admin_list.first_index_of(&co_admin) {
            Some(idx) => idx,
            None => return Err(EscrowError::NotFound),
        };
        admin_list.remove(index);
        env.storage()
            .instance()
            .set(&DataKey::AdminList, &admin_list);
        Ok(true)
    }

    /// Configure the marketplace registry used to reject suspended merchant
    /// sellers when creating new escrows. Admin-only.
    pub fn set_merchant_registry(
        env: Env,
        admin: Address,
        registry: Address,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin) {
            return Err(EscrowError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::MerchantRegistry, &registry);
        Ok(true)
    }

    /// Set authorized merchant categories (MCC codes) for spend validation.
    ///
    /// When set, the escrow contract will validate that the seller's merchant
    /// category matches one of these authorized categories during spend operations.
    /// This enforces merchant category restrictions as configured by the platform.
    ///
    /// Admin-only. Setting an empty list disables category validation.
    pub fn set_authorized_categories(
        env: Env,
        admin: Address,
        categories: soroban_sdk::Vec<Symbol>,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin) {
            return Err(EscrowError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::AuthorizedCategories, &categories);
        Ok(true)
    }

    /// Get the currently authorized merchant categories.
    pub fn get_authorized_categories(env: Env) -> soroban_sdk::Vec<Symbol> {
        env.storage()
            .instance()
            .get(&DataKey::AuthorizedCategories)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Validate that a seller's merchant category is authorized for spending.
    ///
    /// This function checks the marketplace registry to verify the seller's
    /// category matches one of the authorized categories configured on the escrow.
    /// Returns `Ok(())` on success, or `Err(EscrowError::MerchantCategoryNotAllowed)` on failure.
    fn validate_seller_category(
        env: &Env,
        seller: &Address,
    ) -> Result<(), EscrowError> {
        // Get authorized categories
        let authorized_categories = Self::get_authorized_categories(env.clone());

        // If no categories configured, skip validation
        if authorized_categories.is_empty() {
            return Ok(());
        }

        // Get marketplace registry
        let registry: Address = match env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::MerchantRegistry)
        {
            Some(r) => r,
            None => return Ok(()), // No registry, skip validation
        };

        // Try calling the marketplace to validate merchant category by seller address
        let result = env.try_invoke_contract::<u64, EscrowError>(
            &registry,
            &Symbol::new(env, "get_merchant_id_by_owner"),
            soroban_sdk::vec![env, seller.to_val()],
        );

        let merchant_id = match result {
            Ok(Ok(id)) => id,
            _ => return Ok(()), // If we can't find merchant, allow (fail open)
        };

        // Now validate the category
        let args = soroban_sdk::vec![env, merchant_id.to_val(), authorized_categories.to_val()];
        let validation_result = env.try_invoke_contract::<(), EscrowError>(
            &registry,
            &Symbol::new(env, "validate_merchant_category"),
            args,
        );

        match validation_result {
            Ok(Ok(())) => Ok(()),
            _ => Err(EscrowError::MerchantCategoryNotAllowed),
        }
    }

    /// Configure the Ed25519 public key authorized to sign delivery proofs.
    /// Admin-only; changing this key immediately changes which proofs are valid.
    pub fn set_oracle_public_key(
        env: Env,
        admin: Address,
        public_key: BytesN<32>,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin) {
            return Err(EscrowError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::OraclePublicKey, &public_key);
        Ok(true)
    }

    /// Set or clear the admin pause flag for new escrow creation. Admin-only.
    pub fn set_create_paused(env: Env, admin: Address, paused: bool) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        let pause_state = EscrowPauseState {
            create_paused: paused,
            updated_by: admin.clone(),
            updated_at_ledger: env.ledger().sequence(),
            expires_at_ledger: None,
        };
        env.storage()
            .instance()
            .set(&DataKey::PauseState, &pause_state);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("paused")),
            EscrowPauseChangedEvent {
                paused,
                admin,
                ledger: env.ledger().sequence(),
            },
        );
        Ok(true)
    }

    /// Set an emergency pause with automatic expiry after specified duration in ledgers.
    /// Admin-only. The pause auto-expires after `duration_ledgers` ledgers.
    pub fn set_emergency_pause(
        env: Env,
        admin: Address,
        paused: bool,
        duration_ledgers: u32,
    ) -> Result<bool, EscrowError> {
        admin.require_auth();
        if !Self::is_admin(env.clone(), admin.clone()) {
            return Err(EscrowError::Unauthorized);
        }
        let current_ledger = env.ledger().sequence();
        let expires_at = if paused && duration_ledgers > 0 {
            Some(current_ledger.saturating_add(duration_ledgers))
        } else {
            None
        };
        let pause_state = EscrowPauseState {
            create_paused: paused,
            updated_by: admin.clone(),
            updated_at_ledger: current_ledger,
            expires_at_ledger: expires_at,
        };
        env.storage()
            .instance()
            .set(&DataKey::PauseState, &pause_state);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("paused")),
            EscrowPauseChangedEvent {
                paused,
                admin,
                ledger: current_ledger,
            },
        );
        Ok(true)
    }

    /// Get the current escrow creation pause state.
    /// Returns false if pause has expired.
    pub fn get_create_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, EscrowPauseState>(&DataKey::PauseState)
            .map(|s| {
                if let Some(expires_at) = s.expires_at_ledger {
                    s.create_paused && env.ledger().sequence() < expires_at
                } else {
                    s.create_paused
                }
            })
            .unwrap_or(false)
    }

    /// Get the token address associated with an escrow.
    pub fn get_token(env: Env, escrow_id: u64) -> Result<EscrowTokenView, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        Ok(EscrowTokenView {
            escrow_id,
            token: record.token,
        })
    }

    /// Get the optional metadata for an escrow.
    ///
    /// Returns the metadata if it was provided during escrow creation.
    /// Returns [`EscrowError::NotFound`] when no escrow exists for
    /// `escrow_id`, or [`EscrowError::MetadataNotSet`] when the escrow
    /// exists but no metadata was stored.
    pub fn get_escrow_metadata(env: Env, escrow_id: u64) -> Result<EscrowMetadata, EscrowError> {
        let escrow: EscrowRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(EscrowError::NotFound)?;
        let _ = escrow;

        let order_hash: Option<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowMetadataHash(escrow_id));
        let schema: Option<Symbol> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowMetadataSchema(escrow_id));

        let order_hash = order_hash.ok_or(EscrowError::MetadataNotSet)?;
        let schema = schema.ok_or(EscrowError::MetadataNotSet)?;
        Ok(EscrowMetadata { order_hash, schema })
    }

    /// Fill in (or overwrite) the order-hash half of an escrow's metadata
    /// after creation (issue #39). Buyer or admin only. Useful when an escrow
    /// was created with only a schema, or with no metadata at all.
    pub fn set_escrow_metadata_hash(
        env: Env,
        escrow_id: u64,
        caller: Address,
        order_hash: BytesN<32>,
    ) -> Result<(), EscrowError> {
        caller.require_auth();

        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(EscrowError::NotFound)?;
        if caller != record.buyer && !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::EscrowMetadataHash(escrow_id), &order_hash);
        Ok(())
    }

    /// Fill in (or overwrite) the schema half of an escrow's metadata after
    /// creation (issue #39). Buyer or admin only. Useful when an escrow was
    /// created with only a hash, or with no metadata at all.
    pub fn set_escrow_metadata_schema(
        env: Env,
        escrow_id: u64,
        caller: Address,
        schema: Symbol,
    ) -> Result<(), EscrowError> {
        caller.require_auth();

        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .ok_or(EscrowError::NotFound)?;
        if caller != record.buyer && !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::EscrowMetadataSchema(escrow_id), &schema);
        Ok(())
    }

    /// Returns true if the address is the primary admin or a co-admin.
    /// Read-only check: returns whether the given caller is eligible to refund
    /// the specified escrow, and a machine-readable reason symbol (issue #173).
    ///
    /// Reason symbols (≤7 chars for `symbol_short!` compat):
    ///   `ok`       — caller may refund right now
    ///   `notfund`  — escrow not found
    ///   `released` — already released (terminal)
    ///   `refunded` — already refunded (terminal)
    ///   `disputed` — escrow is under dispute
    ///   `noauth`   — caller is not buyer/seller/admin
    ///   `timeout`  — buyer must wait for timeout
    pub fn get_refund_eligibility(env: Env, escrow_id: u64, caller: Address) -> RefundEligibility {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => {
                return RefundEligibility {
                    escrow_id,
                    eligible: false,
                    reason: symbol_short!("notfund"),
                };
            }
        };

        // Terminal states
        if record.status == EscrowStatus::Released {
            return RefundEligibility {
                escrow_id,
                eligible: false,
                reason: symbol_short!("released"),
            };
        }
        if record.status == EscrowStatus::Refunded {
            return RefundEligibility {
                escrow_id,
                eligible: false,
                reason: symbol_short!("refunded"),
            };
        }
        if record.status == EscrowStatus::Cancelled {
            return RefundEligibility {
                escrow_id,
                eligible: false,
                reason: symbol_short!("cancelled"),
            };
        }
        if record.status == EscrowStatus::Created {
            return RefundEligibility {
                escrow_id,
                eligible: false,
                reason: symbol_short!("unfunded"),
            };
        }
        if record.status == EscrowStatus::Disputed {
            return RefundEligibility {
                escrow_id,
                eligible: false,
                reason: symbol_short!("disputed"),
            };
        }

        // Must be Funded at this point
        let is_seller = caller == record.seller;
        let is_buyer = caller == record.buyer;
        let is_admin = Self::is_admin(env.clone(), caller.clone());

        if is_seller || is_admin {
            return RefundEligibility {
                escrow_id,
                eligible: true,
                reason: symbol_short!("ok"),
            };
        }

        if is_buyer {
            let timeout_reached = env.ledger().sequence() >= record.timeout_ledger;
            if timeout_reached {
                return RefundEligibility {
                    escrow_id,
                    eligible: true,
                    reason: symbol_short!("ok"),
                };
            } else {
                return RefundEligibility {
                    escrow_id,
                    eligible: false,
                    reason: symbol_short!("timeout"),
                };
            }
        }

        RefundEligibility {
            escrow_id,
            eligible: false,
            reason: symbol_short!("noauth"),
        }
    }

    /// Read-only timeout metadata for a single escrow (issue #88).
    ///
    /// Returns the timeout ledger, the current ledger, and whether the buyer
    /// is currently eligible to trigger a refund based purely on the timeout.
    /// The getter does **not** mutate any contract state — safe to call at any
    /// time without auth.
    ///
    /// `refundable` is `true` only when the escrow is still `Funded` **and**
    /// `current_ledger >= timeout_ledger`.  Terminal states (`Released`,
    /// `Refunded`) and disputed escrows always return `refundable: false`.
    ///
    /// # Errors
    /// Returns [`EscrowError::NotFound`] when no escrow exists for `escrow_id`.
    pub fn get_timeout_view(env: Env, escrow_id: u64) -> Result<EscrowTimeoutView, EscrowError> {
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;

        let current_ledger = env.ledger().sequence();
        let timeout_ledger = record.timeout_ledger;

        // Only a Funded escrow can become refundable via timeout.
        // Released, Refunded, and Disputed states are not refundable here.
        let refundable = record.status == EscrowStatus::Funded && current_ledger >= timeout_ledger;

        Ok(EscrowTimeoutView {
            escrow_id: record.order_id,
            timeout_ledger,
            current_ledger,
            refundable,
        })
    }

    fn validate_release_status(record: &EscrowRecord) -> Result<(), EscrowError> {
        if record.status == EscrowStatus::Released {
            return Err(EscrowError::AlreadyReleased);
        }

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        Ok(())
    }

    /// Computes yield accrued on an escrow's remaining principal for the time
    /// it has been held, based on the given `YieldConfig` APR.  The principal
    /// is `record.amount - record.released_amount - record.refunded_amount`
    /// so partially settled escrows report honest yield (issue #33). Returns
    /// `(yield_amount, held_seconds)`; `(0, 0)` when no yield config is set.
    fn compute_yield(
        record: &EscrowRecord,
        yield_config: Option<&YieldConfig>,
        env: &Env,
    ) -> (i128, u64) {
        match yield_config {
            Some(cfg) => {
                let held_seconds = env.ledger().timestamp().saturating_sub(record.created_at);
                let remaining =
                    record.amount - record.released_amount - record.refunded_amount;
                let yield_amount = (remaining * cfg.apr_bps as i128 * held_seconds as i128)
                    / (10_000i128 * SECONDS_PER_YEAR);
                (yield_amount, held_seconds)
            }
            None => (0, 0),
        }
    }

    fn release_block_reason(env: Env, record: &EscrowRecord) -> Option<Symbol> {
        match record.status {
            EscrowStatus::Funded => {
                if env.ledger().sequence() >= record.timeout_ledger {
                    Some(symbol_short!("timeout"))
                } else {
                    None
                }
            }
            EscrowStatus::Created => Some(symbol_short!("unfunded")),
            EscrowStatus::Released => Some(symbol_short!("released")),
            EscrowStatus::Refunded => Some(symbol_short!("refunded")),
            EscrowStatus::Disputed => Some(symbol_short!("disputed")),
            EscrowStatus::Cancelled => Some(symbol_short!("cancelled")),
        }
    }

    /// Release escrowed funds split among multiple recipients (#321).
    ///
    /// `shares` is a list of `(recipient, amount)` pairs. The sum of all
    /// amounts must not exceed the remaining escrow balance. A platform fee
    /// is deducted from each individual share before transfer.
    /// Only the buyer or an admin may call this.
    pub fn split_release(
        env: Env,
        escrow_id: u64,
        caller: Address,
        shares: Vec<(Address, i128)>,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if caller != record.buyer && !Self::is_admin(env.clone(), caller.clone()) {
            return Err(EscrowError::Unauthorized);
        }

        check_not_terminal(&record)?;

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        // Validate total split amount
        let remaining = record.amount - record.released_amount - record.refunded_amount;
        let mut total: i128 = 0;
        for (_, amount) in shares.iter() {
            if amount <= 0 {
                return Err(EscrowError::InvalidAmount);
            }
            total += amount;
        }
        if total > remaining {
            return Err(EscrowError::InsufficientEscrowBalance);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &record.token);

        let mut total_fee: i128 = 0;
        let mut total_released: i128 = 0;

        for (recipient, amount) in shares.iter() {
            let fee = Self::compute_fee_amount(&env, amount)?;
            let net = amount - fee;

            token_client.transfer(&env.current_contract_address(), &recipient, &net);

            total_fee += fee;
            total_released += amount;
        }

        Self::distribute_fee(&env, &token_client, total_fee)?;

        record.released_amount += total_released;
        let new_remaining = record.amount - record.released_amount - record.refunded_amount;
        if new_remaining == 0 {
            record.status = EscrowStatus::Released;
        }
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        // #45: A split release that exhausts the escrow balance is a terminal
        // payout path, so it reports the yield accrued over the holding period
        // just like the other terminal payout paths.
        if new_remaining == 0 {
            let yield_config: Option<YieldConfig> = env
                .storage()
                .persistent()
                .get(&DataKey::EscrowYieldConfig(escrow_id));
            if let Some(cfg) = &yield_config {
                let (yield_amount, held_seconds) = Self::compute_yield(&record, Some(cfg), &env);
                env.events().publish(
                    (symbol_short!("escrow"), symbol_short!("yield"), escrow_id),
                    EscrowYieldAccruedEvent {
                        escrow_id,
                        seller: record.seller.clone(),
                        yield_amount,
                        held_seconds,
                    },
                );
            }
        }

        env.events().publish(
            (
                symbol_short!("escrow"),
                symbol_short!("splitrel"),
                escrow_id,
            ),
            EscrowSplitReleasedEvent {
                escrow_id,
                recipient_count: shares.len(),
                total_released,
                fee_charged: total_fee,
                released_by: caller,
            },
        );

        Ok(true)
    }

    /// Extend the timeout ledger of a `Funded` escrow (#323).
    ///
    /// Requires mutual authentication from both buyer and seller (both must
    /// sign the transaction), OR unilateral authorization from an admin.
    /// `new_timeout_ledger` must be strictly greater than the current value.
    pub fn extend_timeout(
        env: Env,
        escrow_id: u64,
        caller: Address,
        new_timeout_ledger: u32,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();

        let key = DataKey::Escrow(escrow_id);
        let mut record: EscrowRecord = match env.storage().persistent().get(&key) {
            Some(rec) => rec,
            None => return Err(EscrowError::NotFound),
        };

        if record.status != EscrowStatus::Funded {
            return Err(EscrowError::InvalidStatus);
        }

        if new_timeout_ledger <= record.timeout_ledger {
            return Err(EscrowError::InvalidExtension);
        }

        // Authorization: admin can do it alone; otherwise both buyer AND seller must sign.
        if !Self::is_admin(env.clone(), caller.clone()) {
            // Caller must be either buyer or seller, and both must authenticate.
            if caller != record.buyer && caller != record.seller {
                return Err(EscrowError::Unauthorized);
            }
            record.buyer.require_auth();
            record.seller.require_auth();
        }

        let old_timeout = record.timeout_ledger;
        record.timeout_ledger = new_timeout_ledger;
        record.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("exttime"), escrow_id),
            EscrowTimeoutExtendedEvent {
                escrow_id,
                old_timeout_ledger: old_timeout,
                new_timeout_ledger,
                extended_by: caller,
            },
        );

        Ok(true)
    }

    /// Paginated enumeration of all escrows (issue #49).
    ///
    /// Returns up to `min(limit, MAX_PAGE_LIMIT)` [`EscrowRecord`]s starting
    /// at zero-based `offset`. The global escrow ID list is maintained by
    /// `create_internal`, so records are returned in creation order.
    ///
    /// `page.total`       — total number of escrows ever created.
    /// `page.next_offset` — `Some(next)` when another page follows; `None` on
    ///                      the last page.
    pub fn list_escrows(env: Env, offset: u32, limit: u32) -> EscrowListPage {
        let all_ids: soroban_sdk::Vec<u64> = env
            .storage()
            .instance()
            .get(&DataKey::EscrowIds)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));

        let total = all_ids.len();
        let capped_limit = limit.min(MAX_PAGE_LIMIT);
        let start = offset.min(total);
        let end = (start + capped_limit).min(total);

        let mut items = soroban_sdk::Vec::new(&env);
        for i in start..end {
            let escrow_id = all_ids.get(i).unwrap();
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<DataKey, EscrowRecord>(&DataKey::Escrow(escrow_id))
            {
                items.push_back(record);
            }
        }

        let count = end - start;
        let next_offset = if end < total {
            Some(start + count)
        } else {
            None
        };

        EscrowListPage {
            items,
            total,
            next_offset,
        }
    }

    /// Paginated enumeration of escrows for a specific buyer (issue #49).
    ///
    /// Returns up to `min(limit, MAX_PAGE_LIMIT)` [`EscrowRecord`]s belonging
    /// to `buyer`, starting at zero-based `offset` within that buyer's index.
    /// The per-buyer index is maintained by `create_internal` in creation order.
    ///
    /// `page.total`       — total number of escrows created by this buyer.
    /// `page.next_offset` — `Some(next)` when another page follows; `None` on
    ///                      the last page.
    pub fn list_escrows_by_buyer(
        env: Env,
        buyer: Address,
        offset: u32,
        limit: u32,
    ) -> EscrowListPage {
        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::BuyerEscrowCount(buyer.clone()))
            .unwrap_or(0);
        let capped_limit = limit.min(MAX_PAGE_LIMIT);
        let start = offset.min(total);
        let end = start.saturating_add(capped_limit).min(total);

        let mut items = soroban_sdk::Vec::new(&env);
        for i in start..end {
            let escrow_id: u64 = env
                .storage()
                .persistent()
                .get(&DataKey::BuyerEscrowAt(buyer.clone(), i))
                .unwrap();
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<DataKey, EscrowRecord>(&DataKey::Escrow(escrow_id))
            {
                items.push_back(record);
            }
        }

        let count = end - start;
        let next_offset = if end < total {
            Some(start + count)
        } else {
            None
        };

        EscrowListPage {
            items,
            total,
            next_offset,
        }
    }

    pub fn is_admin(env: Env, address: Address) -> bool {
        let primary_admin: Address = match env.storage().instance().get(&DataKey::Admin) {
            Some(addr) => addr,
            None => return false,
        };
        if address == primary_admin {
            return true;
        }
        let admin_list: soroban_sdk::Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        admin_list.contains(&address)
    }

    /// Configured upgrade threshold, defaulting to [`MIN_UPGRADE_THRESHOLD`].
    fn upgrade_threshold(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::UpgradeThreshold)
            .unwrap_or(MIN_UPGRADE_THRESHOLD)
    }

    /// Size of the upgrade signer set: the primary admin plus co-admins.
    fn upgrade_signer_count(env: &Env) -> u32 {
        let co_admins: soroban_sdk::Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
        let has_primary = env.storage().instance().has(&DataKey::Admin);
        co_admins.len() + u32::from(has_primary)
    }

    /// The stored upgrade proposal, if it has not been executed yet.
    fn pending_upgrade_proposal(env: &Env) -> Option<UpgradeProposal> {
        env.storage()
            .instance()
            .get::<DataKey, UpgradeProposal>(&DataKey::UpgradeProposal)
            .filter(|p| !p.executed)
    }

    /// Count approvals from addresses that are still admins, so approvals
    /// from since-removed co-admins do not count toward the threshold.
    fn valid_upgrade_approvals(env: &Env, approvals: &Vec<Address>) -> u32 {
        approvals
            .iter()
            .filter(|a| Self::is_admin(env.clone(), a.clone()))
            .count() as u32
    }

    // ── Ticket 1: clear_release_condition ────────────────────────────────────

    /// Remove the release condition for an escrow. Admin or co-admin only.
    ///
    /// Useful when the configured oracle becomes unavailable or the condition
    /// is no longer required. Blocked on escrows that have already reached a
    /// terminal state (Released or Refunded) — those escrows are already
    /// settled so clearing the condition would have no effect and signals a
    /// caller logic error.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if `caller` is neither the primary
    ///   admin nor a co-admin.
    /// - [`EscrowError::NotFound`] if `escrow_id` does not exist.
    /// - [`EscrowError::AlreadyReleased`] if the escrow has been released.
    /// - [`EscrowError::AlreadyRefunded`] if the escrow has been refunded.
    /// - [`EscrowError::AlreadyCancelled`] if the escrow has been cancelled.
    pub fn clear_release_condition(
        env: Env,
        caller: Address,
        escrow_id: u64,
    ) -> Result<(), EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller) {
            return Err(EscrowError::Unauthorized);
        }
        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        check_not_terminal(&record)?;
        env.storage()
            .persistent()
            .remove(&DataKey::ReleaseCondition(escrow_id));
        Ok(())
    }

    /// Enable or disable the release-condition gate for buyer-originated
    /// releases on an escrow (issue #48). Admin-only.
    ///
    /// When `require` is `true`, buyer-originated `partial_release`/`release`
    /// on this escrow are blocked unless `get_release_eligibility` returns
    /// eligible. The default is `false` for backward compatibility.
    pub fn set_require_release_condition(
        env: Env,
        caller: Address,
        escrow_id: u64,
        require: bool,
    ) -> Result<bool, EscrowError> {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller) {
            return Err(EscrowError::Unauthorized);
        }

        let key = DataKey::Escrow(escrow_id);
        let record: EscrowRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::NotFound)?;
        check_not_terminal(&record)?;

        env.storage()
            .persistent()
            .set(&DataKey::RequireReleaseCondition(escrow_id), &require);
        Ok(true)
    }

    /// Read-only getter for whether buyer-originated releases on an escrow are
    /// gated on the release condition. Defaults to `false` when unset.
    pub fn get_require_release_condition(env: Env, escrow_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::RequireReleaseCondition(escrow_id))
            .unwrap_or(false)
    }

    // ── Ticket 2: get_yield_config ────────────────────────────────────────────

    /// Read-only getter for the yield configuration of an escrow.
    ///
    /// Returns `None` when no yield config has been set via `set_yield_config`.
    /// Never mutates storage.
    pub fn get_yield_config(env: Env, escrow_id: u64) -> Option<YieldConfig> {
        env.storage()
            .persistent()
            .get(&DataKey::EscrowYieldConfig(escrow_id))
    }

    // ── Ticket 3: get_co_admins / get_pending_admin ───────────────────────────

    /// Read-only getter for the list of co-admins.
    ///
    /// Returns an empty `Vec` when no co-admins have been added — never
    /// panics on missing state. Never mutates storage.
    pub fn get_co_admins(env: Env) -> soroban_sdk::Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Read-only getter for the pending (proposed) new primary admin.
    ///
    /// Returns `None` when no admin transfer is in progress. Never mutates
    /// storage.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }
}

#[cfg(test)]
mod escrow_feature_tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        token::StellarAssetClient,
        TryIntoVal,
    };

    fn setup(env: &Env) -> (
        EscrowContractClient<'_>,
        Address,
        Address,
        Address,
        Address,
        Address,
    ) {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let buyer = Address::generate(env);
        let seller = Address::generate(env);
        let token = env
            .register_stellar_asset_contract_v2(Address::generate(env))
            .address();
        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps: 250,
            treasury,
            min_amount: 100,
            max_amount: 1_000_000,
        };
        let contract_id = env.register(EscrowContract, (config,));
        let client = EscrowContractClient::new(env, &contract_id);
        StellarAssetClient::new(env, &token).mint(&buyer, &10_000);
        client.add_token(&admin, &token);
        (client, admin, buyer, seller, token, contract_id)
    }

    fn order_leaf(env: &Env, order_id: &BytesN<32>) -> BytesN<32> {
        env.crypto()
            .sha256(&Bytes::from_array(env, &order_id.to_array()))
            .into()
    }

    #[test]
    fn published_root_releases_only_the_committed_order() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, _) = setup(&env);
        let order_id = BytesN::from_array(&env, &[91; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000, &order_id, &1_000, &None, &None,
        );
        let date = 20u64;
        let leaf = order_leaf(&env, &order_id);
        client.publish_merkle_root(&admin, &date, &leaf);
        let proof = MerkleDeliveryProof {
            root: leaf.clone(),
            leaf,
            proof: Vec::new(&env),
            index: 0,
        };

        assert_eq!(
            client.try_publish_merkle_root(&admin, &date, &proof.root),
            Err(Ok(EscrowError::MerkleRootAlreadyPublished))
        );
        assert!(client.release_with_merkle_proof(&escrow_id, &buyer, &date, &proof));
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Released);
    }

    #[test]
    fn merkle_path_uses_index_to_order_siblings() {
        let env = Env::default();
        let left = BytesN::from_array(&env, &[1; 32]);
        let right = BytesN::from_array(&env, &[2; 32]);
        let mut node = Bytes::new(&env);
        node.append(&Bytes::from_array(&env, &left.to_array()));
        node.append(&Bytes::from_array(&env, &right.to_array()));
        let root: BytesN<32> = env.crypto().sha256(&node).into();
        let proof = MerkleDeliveryProof {
            root,
            leaf: right,
            proof: Vec::from_array(&env, [left]),
            index: 1,
        };

        assert!(EscrowContract::verify_merkle_path(&env, &proof));
        let mut invalid = proof;
        invalid.index = 0;
        assert!(!EscrowContract::verify_merkle_path(&env, &invalid));
    }

    #[test]
    fn merkle_release_rejects_a_leaf_for_another_order() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, _) = setup(&env);
        let order_id = BytesN::from_array(&env, &[11; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000, &order_id, &1_000, &None, &None,
        );
        let date = 21u64;
        let committed = order_leaf(&env, &order_id);
        client.publish_merkle_root(&admin, &date, &committed);
        let proof = MerkleDeliveryProof {
            root: committed,
            leaf: BytesN::from_array(&env, &[12; 32]),
            proof: Vec::new(&env),
            index: 0,
        };

        assert_eq!(
            client.try_release_with_merkle_proof(&escrow_id, &buyer, &date, &proof),
            Err(Ok(EscrowError::InvalidMerkleProof))
        );
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Funded);
    }

    #[test]
    fn merkle_release_settles_only_the_unrefunded_balance() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, contract_id) = setup(&env);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let order_id = BytesN::from_array(&env, &[13; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000, &order_id, &1_000, &None, &None,
        );
        client.partial_refund(&escrow_id, &seller, &200);
        let date = 22u64;
        let leaf = order_leaf(&env, &order_id);
        client.publish_merkle_root(&admin, &date, &leaf);
        let proof = MerkleDeliveryProof {
            root: leaf.clone(),
            leaf,
            proof: Vec::new(&env),
            index: 0,
        };

        assert!(client.release_with_merkle_proof(&escrow_id, &buyer, &date, &proof));
        let record = client.get_escrow(&escrow_id);
        assert_eq!(record.released_amount, 800);
        assert_eq!(record.refunded_amount, 200);
        assert_eq!(record.status, EscrowStatus::Released);
        assert_eq!(token_client.balance(&contract_id), 0);
    }

    #[test]
    fn batch_escrows_pull_aggregated_token_allowance_once() {
        let env = Env::default();
        let (client, _admin, buyer, seller, token, contract_id) = setup(&env);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let timeout = env.ledger().sequence() + 500;
        token_client.approve(&buyer, &contract_id, &2_500, &(timeout + 100));
        let items = Vec::from_array(
            &env,
            [
                BatchEscrowItem {
                    seller: seller.clone(),
                    token: token.clone(),
                    amount: 1_000,
                    order_id: BytesN::from_array(&env, &[31; 32]),
                    timeout_ledger: timeout,
                },
                BatchEscrowItem {
                    seller,
                    token: token.clone(),
                    amount: 1_500,
                    order_id: BytesN::from_array(&env, &[32; 32]),
                    timeout_ledger: timeout,
                },
            ],
        );

        let ids = client.batch_create_escrows(&buyer, &items);
        assert_eq!(ids.len(), 2);
        assert_eq!(token_client.balance(&buyer), 7_500);
        assert_eq!(token_client.balance(&contract_id), 2_500);
        assert_eq!(
            client.get_escrow(&ids.get(0).unwrap()).timeout_ledger,
            timeout
        );
        assert_eq!(
            client.get_escrow(&ids.get(1).unwrap()).status,
            EscrowStatus::Funded
        );
    }

    #[test]
    fn batch_escrow_allowance_failure_reverts_all_items() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, contract_id) = setup(&env);
        let token_admin = Address::generate(&env);
        let second_token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let second_admin = soroban_sdk::token::StellarAssetClient::new(&env, &second_token);
        second_admin.mint(&buyer, &10_000);
        client.add_token(&admin, &second_token);

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let second_client = soroban_sdk::token::Client::new(&env, &second_token);
        let timeout = env.ledger().sequence() + 500;
        token_client.approve(&buyer, &contract_id, &1_000, &(timeout + 100));
        let items = Vec::from_array(
            &env,
            [
                BatchEscrowItem {
                    seller: seller.clone(),
                    token: token.clone(),
                    amount: 1_000,
                    order_id: BytesN::from_array(&env, &[41; 32]),
                    timeout_ledger: timeout,
                },
                BatchEscrowItem {
                    seller,
                    token: second_token.clone(),
                    amount: 1_000,
                    order_id: BytesN::from_array(&env, &[42; 32]),
                    timeout_ledger: timeout,
                },
            ],
        );

        assert!(client.try_batch_create_escrows(&buyer, &items).is_err());
        assert!(client.try_get_escrow(&1).is_err());
        assert_eq!(token_client.balance(&buyer), 10_000);
        assert_eq!(second_client.balance(&buyer), 10_000);
        assert_eq!(token_client.balance(&contract_id), 0);
        assert_eq!(second_client.balance(&contract_id), 0);
    }

    #[test]
    fn split_dispute_pays_all_award_recipients_and_emits_event() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, contract_id) = setup(&env);
        let mediator = Address::generate(&env);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let escrow_id = client.deposit(
            &buyer,
            &seller,
            &token,
            &1_000,
            &BytesN::from_array(&env, &[51; 32]),
            &1_000,
            &None,
            &None,
        );
        client.dispute(&escrow_id, &buyer);

        let award = DisputeResolutionAward {
            buyer_amount: 700,
            seller_amount: 250,
            mediator_fee: 50,
            mediator_address: mediator.clone(),
        };
        assert!(client.resolve_dispute_split(&escrow_id, &admin, &award));

        let events = env.events().all();
        let mut found_event = false;
        for (event_contract, topics, data) in events.iter() {
            if event_contract != contract_id || topics.len() != 3 {
                continue;
            }
            let topic: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if topic == symbol_short!("dispsplit") {
                let event: DisputeResolvedEvent = data.try_into_val(&env).unwrap();
                assert_eq!(event.escrow_id, escrow_id);
                assert_eq!(event.buyer_amount, 700);
                assert_eq!(event.seller_amount, 250);
                assert_eq!(event.mediator_fee, 50);
                assert_eq!(event.mediator_address, mediator);
                found_event = true;
            }
        }
        assert!(found_event);

        assert_eq!(token_client.balance(&buyer), 9_700);
        assert_eq!(token_client.balance(&seller), 250);
        assert_eq!(token_client.balance(&mediator), 50);
        assert_eq!(token_client.balance(&contract_id), 0);
        let record = client.get_escrow(&escrow_id);
        assert_eq!(record.status, EscrowStatus::Released);
        assert_eq!(record.released_amount, 300);
        assert_eq!(record.refunded_amount, 700);
    }

    #[test]
    fn split_dispute_rejects_awards_that_do_not_match_escrow_amount() {
        let env = Env::default();
        let (client, admin, buyer, seller, token, contract_id) = setup(&env);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let escrow_id = client.deposit(
            &buyer,
            &seller,
            &token,
            &1_000,
            &BytesN::from_array(&env, &[52; 32]),
            &1_000,
            &None,
            &None,
        );
        client.dispute(&escrow_id, &buyer);
        let award = DisputeResolutionAward {
            buyer_amount: 700,
            seller_amount: 250,
            mediator_fee: 49,
            mediator_address: Address::generate(&env),
        };

        assert_eq!(
            client.try_resolve_dispute_split(&escrow_id, &admin, &award),
            Err(Ok(EscrowError::InvalidDisputeAward))
        );
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Disputed);
        assert_eq!(token_client.balance(&contract_id), 1_000);
    }
}

#[cfg(test)]
mod fee_distribution_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup(env: &Env) -> (EscrowContractClient<'_>, Address, Address) {
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps: 250u32,
            treasury: treasury.clone(),
            min_amount: 100i128,
            max_amount: 1_000_000i128,
        };
        let contract_id = env.register(EscrowContract, (config,));
        let client = EscrowContractClient::new(env, &contract_id);
        env.mock_all_auths();
        (client, admin, contract_id)
    }

    #[test]
    fn rejects_zero_address_treasury() {
        let env = Env::default();
        let (client, admin, _contract_id) = setup(&env);
        let shares = soroban_sdk::vec![
            &env,
            TreasuryShare {
                treasury: Address::from_str(&env, ZERO_ACCOUNT_STRKEY),
                bps: 100,
            }
        ];

        let res = client.try_set_fee_distribution(&admin, &shares);
        assert_eq!(res, Err(Ok(EscrowError::InvalidAddress)));
    }

    #[test]
    fn rejects_zero_bps_share() {
        let env = Env::default();
        let (client, admin, _contract_id) = setup(&env);
        let treasury = Address::generate(&env);
        let shares = soroban_sdk::vec![&env, TreasuryShare { treasury, bps: 0 }];

        let res = client.try_set_fee_distribution(&admin, &shares);
        assert_eq!(res, Err(Ok(EscrowError::InvalidFeeBps)));
    }

    #[test]
    fn rejects_too_many_treasuries() {
        let env = Env::default();
        let (client, admin, _contract_id) = setup(&env);
        let mut shares = Vec::new(&env);
        for _ in 0..=MAX_TREASURIES {
            shares.push_back(TreasuryShare {
                treasury: Address::generate(&env),
                bps: 1,
            });
        }

        let res = client.try_set_fee_distribution(&admin, &shares);
        assert_eq!(res, Err(Ok(EscrowError::MaxTreasuriesExceeded)));
    }

    #[test]
    fn accepts_multi_treasury_distribution() {
        let env = Env::default();
        let (client, admin, _contract_id) = setup(&env);
        let treasury1 = Address::generate(&env);
        let treasury2 = Address::generate(&env);
        let shares = soroban_sdk::vec![
            &env,
            TreasuryShare {
                treasury: treasury1.clone(),
                bps: 300,
            },
            TreasuryShare {
                treasury: treasury2.clone(),
                bps: 200,
            },
        ];

        assert!(client.set_fee_distribution(&admin, &shares.clone()));
        assert_eq!(client.get_fee_distribution(), shares);
    }
}

#[cfg(test)]
mod batch_flow_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn batch_release_missing_escrow_returns_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps: 250u32,
            treasury: treasury.clone(),
            min_amount: 100i128,
            max_amount: 1_000_000i128,
        };
        let contract_id = env.register(EscrowContract, (config,));
        let client = EscrowContractClient::new(&env, &contract_id);

        let caller = Address::generate(&env);
        let releases = soroban_sdk::vec![
            &env,
            BatchReleaseParams {
                escrow_id: 999,
                release_amount: 1,
            }
        ];

        assert_eq!(
            client.try_batch_release(&caller, &releases),
            Err(Ok(EscrowError::NotFound))
        );
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup(env: &Env) -> (EscrowContractClient<'_>, Address, Address) {
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps: 250u32,
            treasury: treasury.clone(),
            min_amount: 100i128,
            max_amount: 1_000_000i128,
        };
        let contract_id = env.register(EscrowContract, (config,));
        let client = EscrowContractClient::new(env, &contract_id);
        (client, admin, contract_id)
    }

    fn setup_with_token(env: &Env) -> (EscrowContractClient<'_>, Address, Address, Address) {
        let (client, admin, contract_id) = setup(env);
        env.mock_all_auths();
        let token_admin = Address::generate(env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);
        (client, admin, contract_id, token)
    }

    #[test]
    fn get_escrow_metadata_absent_escrow_returns_not_found() {
        let env = Env::default();
        let (client, _admin, _contract_id) = setup(&env);
        let result = client.try_get_escrow_metadata(&999u64);
        assert_eq!(result, Err(Ok(EscrowError::NotFound)));
    }

    #[test]
    fn get_escrow_metadata_existing_without_metadata_returns_metadata_not_set() {
        let env = Env::default();
        let (client, _admin, _contract_id, token) = setup_with_token(&env);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let order_id = BytesN::from_array(&env, &[0u8; 32]);
        let no_hash: Option<BytesN<32>> = None;
        let no_schema: Option<Symbol> = None;
        let escrow_id = client.create(
            &buyer, &seller, &token, &100i128, &order_id, &1000u32, &no_hash, &no_schema,
        );
        let result = client.try_get_escrow_metadata(&escrow_id);
        assert_eq!(result, Err(Ok(EscrowError::MetadataNotSet)));
    }

    #[test]
    fn get_escrow_metadata_existing_with_metadata_returns_metadata() {
        let env = Env::default();
        let (client, _admin, _contract_id, token) = setup_with_token(&env);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let order_id = BytesN::from_array(&env, &[7u8; 32]);
        let order_hash = BytesN::from_array(&env, &[1u8; 32]);
        let schema = Symbol::new(&env, "order_v1");
        let escrow_id = client.create(
            &buyer,
            &seller,
            &token,
            &100i128,
            &order_id,
            &1000u32,
            &Some(order_hash.clone()),
            &Some(schema.clone()),
        );
        let metadata = client.get_escrow_metadata(&escrow_id);
        assert_eq!(metadata.order_hash, order_hash);
        assert_eq!(metadata.schema, schema);
    }

    /// Issue #38: a batch entry with only one of order_hash/schema set must be
    /// rejected with a typed error, never silently persisted with stale
    /// metadata. Covers all four Option combinations.
    #[test]
    fn batch_deposit_rejects_half_set_metadata() {
        let env = Env::default();
        let (client, admin, _contract_id, token) = setup_with_token(&env);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &1_000_000i128);

        let order_hash = BytesN::from_array(&env, &[38u8; 32]);
        let schema = Symbol::new(&env, "order_v1");

        // (Both None) — valid: no metadata, and the batch succeeds.
        let mut none_none = soroban_sdk::Vec::new(&env);
        none_none.push_back(BatchDepositParams {
            seller: seller.clone(),
            token: token.clone(),
            amount: 100i128,
            order_id: BytesN::from_array(&env, &[1u8; 32]),
            timeout_ledgers: 1000u32,
            order_hash: None,
            schema: None,
        });
        assert_eq!(client.batch_deposit(&buyer, &none_none).len(), 1);

        // (Both Some) — valid: full metadata stored.
        let mut some_some = soroban_sdk::Vec::new(&env);
        some_some.push_back(BatchDepositParams {
            seller: seller.clone(),
            token: token.clone(),
            amount: 100i128,
            order_id: BytesN::from_array(&env, &[2u8; 32]),
            timeout_ledgers: 1000u32,
            order_hash: Some(order_hash.clone()),
            schema: Some(schema.clone()),
        });
        assert_eq!(client.batch_deposit(&buyer, &some_some).len(), 1);

        // (Some hash only) — rejected with InvalidMetadata.
        let mut hash_only = soroban_sdk::Vec::new(&env);
        hash_only.push_back(BatchDepositParams {
            seller: seller.clone(),
            token: token.clone(),
            amount: 100i128,
            order_id: BytesN::from_array(&env, &[3u8; 32]),
            timeout_ledgers: 1000u32,
            order_hash: Some(order_hash.clone()),
            schema: None,
        });
        assert_eq!(
            client.try_batch_deposit(&buyer, &hash_only),
            Err(Ok(EscrowError::InvalidMetadata))
        );

        // (Schema only) — rejected with InvalidMetadata.
        let mut schema_only = soroban_sdk::Vec::new(&env);
        schema_only.push_back(BatchDepositParams {
            seller: seller.clone(),
            token: token.clone(),
            amount: 100i128,
            order_id: BytesN::from_array(&env, &[4u8; 32]),
            timeout_ledgers: 1000u32,
            order_hash: None,
            schema: Some(schema.clone()),
        });
        assert_eq!(
            client.try_batch_deposit(&buyer, &schema_only),
            Err(Ok(EscrowError::InvalidMetadata))
        );

        // Admin role is exercised only to keep the client bound; unused here.
        let _ = admin;
    }
}

#[cfg(all(test, feature = "full_suite"))]
mod integration_tests;
#[cfg(all(test, feature = "full_suite"))]
mod test;
#[cfg(test)]
mod quorum_cleanup_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn dispute_votes_removed_after_quorum_resolution() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let arbiter1 = Address::generate(&env);
        let arbiter2 = Address::generate(&env);
        let treasury = Address::generate(&env);

        let token = env.register_stellar_asset_contract(admin.clone());
        let token_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_client.mint(&buyer, &1000i128);

        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps: 0u32,
            treasury: treasury.clone(),
            min_amount: 1i128,
            max_amount: 1000i128,
        };
        let contract_id = env.register(EscrowContract, (config,));
        let client = EscrowContractClient::new(&env, &contract_id);
        client.add_token(&admin, &token);

        let arbiters = soroban_sdk::vec![&env, arbiter1.clone(), arbiter2.clone()];
        client.set_quorum_config(&admin, &arbiters, &2u32);

        let order_id = BytesN::from_array(&env, &[0u8; 32]);
        let escrow_id = client.deposit(
            &buyer,
            &seller,
            &token,
            &1000i128,
            &order_id,
            &1000u32,
            &None::<BytesN<32>>,
            &None::<Symbol>,
        );

        client.dispute(&escrow_id, &buyer);

        client.vote_dispute(&escrow_id, &arbiter1, &true);
        client.vote_dispute(&escrow_id, &arbiter2, &true);

        let votes_key = DataKey::DisputeVotes(escrow_id);
        assert!(env.as_contract(&contract_id, || {
            env.storage().persistent().has(&votes_key)
        }));

        client.resolve_dispute_quorum(&escrow_id, &arbiter1);

        assert!(!env.as_contract(&contract_id, || {
            env.storage().persistent().has(&votes_key)
        }));
    }
}

#[cfg(test)]
mod error_code_allocation_tests {
    use super::*;
    const ALLOCATED_RANGES: [(u32, u32); 5] = [
        (400, 999),
        (1_000, 1_999),
        (2_000, 2_999),
        (3_000, 3_999),
        (4_000, 4_999),
    ];
    fn escrow_error_codes() -> [u32; 45] {
        [
            EscrowError::AlreadyInitialized as u32,
            EscrowError::NotFound as u32,
            EscrowError::Unauthorized as u32,
            EscrowError::AlreadyReleased as u32,
            EscrowError::AlreadyRefunded as u32,
            EscrowError::InvalidStatus as u32,
            EscrowError::TimeoutNotReached as u32,
            EscrowError::NotDisputed as u32,
            EscrowError::InvalidAmount as u32,
            EscrowError::TokenNotWhitelisted as u32,
            EscrowError::InsufficientEscrowBalance as u32,
            EscrowError::ZeroAmount as u32,
            EscrowError::NoPendingTransfer as u32,
            EscrowError::InvalidPendingAdmin as u32,
            EscrowError::AdminAlreadyExists as u32,
            EscrowError::InvalidFeeBps as u32,
            EscrowError::AmountBelowMin as u32,
            EscrowError::AmountAboveMax as u32,
            EscrowError::InvalidLimits as u32,
            EscrowError::NotAnArbiter as u32,
            EscrowError::AlreadyVoted as u32,
            EscrowError::InvalidQuorum as u32,
            EscrowError::QuorumNotReached as u32,
            EscrowError::QuorumConfigNotSet as u32,
            EscrowError::ConflictingQuorum as u32,
            EscrowError::CreationPaused as u32,
            EscrowError::AlreadyCancelled as u32,
            EscrowError::AlreadyFunded as u32,
            EscrowError::InvalidExtension as u32,
            EscrowError::PoolNotFound as u32,
            EscrowError::InsufficientPoolBalance as u32,
            EscrowError::InvalidAddress as u32,
            EscrowError::InvalidEscrowParticipants as u32,
            EscrowError::ReleaseConditionNotSet as u32,
            EscrowError::OracleCallFailed as u32,
            EscrowError::ConditionNotMet as u32,
            EscrowError::InvalidYieldConfig as u32,
            EscrowError::AmountLimitsNotSet as u32,
            EscrowError::FeeConfigNotSet as u32,
            EscrowError::InvalidReleaseRecipient as u32,
            EscrowError::MerchantNotTrading as u32,
            EscrowError::MerchantStatusCheckFailed as u32,
            EscrowError::SignedProofRequired as u32,
            EscrowError::InvalidSignedDeliveryProof as u32,
            EscrowError::OraclePublicKeyNotSet as u32,
        ]
    }
    #[test]
    fn escrow_error_codes_are_unique() {
        let mut codes = escrow_error_codes();
        codes.sort_unstable();
        for pair in codes.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate EscrowError code: {}", pair[0]);
        }
    }
    #[test]
    fn cross_contract_ranges_are_disjoint() {
        let mut ranges = ALLOCATED_RANGES;
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            assert!(
                pair[0].1 < pair[1].0,
                "overlapping error-code ranges: {}..={} and {}..={}",
                pair[0].0,
                pair[0].1,
                pair[1].0,
                pair[1].1
            );
        }
    }
    #[test]
    fn escrow_error_codes_avoid_other_contract_ranges() {
        for &code in &escrow_error_codes() {
            if code >= 400 {
                assert!(
                    code <= ALLOCATED_RANGES[0].1,
                    "EscrowError code {} is outside the escrow allocation",
                    code
                );
                for &(lo, hi) in &ALLOCATED_RANGES[1..] {
                    assert!(
                        !(lo..=hi).contains(&code),
                        "EscrowError code {} collides with another contract's range {}..={}",
                        code,
                        lo,
                        hi
                    );
                }
            }
        }
    }
}
