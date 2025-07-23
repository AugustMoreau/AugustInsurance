// SPDX-License-Identifier: MIT
// AugustInsurance Settlement Engine Smart Contract
// Real-time settlement system for healthcare providers

use std::collections::HashMap;
use std::time::Timestamp;
use std::events::Event;
use std::token::ERC20;
use std::math::SafeMath;
use std::oracle::PriceFeed;

// Settlement status enumeration
enum SettlementStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Disputed,
    Refunded,
    PartiallySettled
}

// Payment method types
enum PaymentMethod {
    DirectTransfer,
    StableCoin,
    BankTransfer,
    DigitalWallet,
    CentralBankDigitalCurrency
}

// Settlement record structure
struct Settlement {
    id: u256,
    claim_id: u256,
    provider: address,
    patient: address,
    gross_amount: u256,
    deductible: u256,
    copay: u256,
    net_amount: u256,
    currency: address, // Token contract address
    payment_method: PaymentMethod,
    status: SettlementStatus,
    initiated_at: Timestamp,
    completed_at: Timestamp,
    transaction_hash: bytes32,
    gas_used: u256,
    exchange_rate: u256, // If currency conversion needed
    fees: SettlementFees,
    reconciliation_data: ReconciliationData
}

// Fee structure
struct SettlementFees {
    processing_fee: u256,
    network_fee: u256,
    exchange_fee: u256,
    total_fees: u256,
    fee_recipient: address
}

// Reconciliation data
struct ReconciliationData {
    batch_id: u256,
    reconciled: bool,
    reconciliation_date: Timestamp,
    discrepancy_amount: u256,
    notes: string
}

// Provider settlement preferences
struct ProviderPreferences {
    provider: address,
    preferred_currency: address,
    preferred_payment_method: PaymentMethod,
    minimum_settlement_amount: u256,
    settlement_frequency: SettlementFrequency,
    bank_details: BankDetails,
    auto_settlement_enabled: bool,
    notification_preferences: NotificationPreferences
}

// Settlement frequency options
enum SettlementFrequency {
    Immediate,
    Daily,
    Weekly,
    BiWeekly,
    Monthly
}

// Bank details for traditional transfers
struct BankDetails {
    account_number: string,
    routing_number: string,
    bank_name: string,
    swift_code: string,
    account_holder_name: string
}

// Notification preferences
struct NotificationPreferences {
    email_notifications: bool,
    sms_notifications: bool,
    webhook_url: string,
    notification_threshold: u256
}

// Batch settlement for efficiency
struct SettlementBatch {
    id: u256,
    provider: address,
    settlement_ids: Vec<u256>,
    total_amount: u256,
    batch_status: SettlementStatus,
    created_at: Timestamp,
    processed_at: Timestamp,
    transaction_hash: bytes32
}

// Liquidity pool for instant settlements
struct LiquidityPool {
    token: address,
    total_liquidity: u256,
    available_liquidity: u256,
    reserved_liquidity: u256,
    yield_rate: u256,
    last_rebalance: Timestamp
}

// Events
event SettlementInitiated(settlement_id: u256, claim_id: u256, provider: address, amount: u256);
event SettlementCompleted(settlement_id: u256, provider: address, amount: u256, transaction_hash: bytes32);
event SettlementFailed(settlement_id: u256, reason: string);
event BatchSettlementProcessed(batch_id: u256, provider: address, total_amount: u256);
event ProviderPreferencesUpdated(provider: address);
event LiquidityAdded(token: address, amount: u256, provider: address);
event LiquidityRemoved(token: address, amount: u256, provider: address);
event ExchangeRateUpdated(from_currency: address, to_currency: address, rate: u256);
event DisputeRaised(settlement_id: u256, disputer: address, reason: string);
event ReconciliationCompleted(batch_id: u256, discrepancies: u256);

contract SettlementEngine {
    // State variables
    mapping(u256 => Settlement) public settlements;
    mapping(address => ProviderPreferences) public provider_preferences;
    mapping(u256 => SettlementBatch) public settlement_batches;
    mapping(address => LiquidityPool) public liquidity_pools;
    mapping(address => u256) public provider_balances;
    mapping(address => Vec<u256>) public provider_settlements;
    mapping(address => mapping(address => u256)) public exchange_rates;
    
    u256 public next_settlement_id;
    u256 public next_batch_id;
    u256 public total_settlements_processed;
    u256 public total_volume_settled;
    u256 public total_fees_collected;
    
    // Supported currencies and tokens
    mapping(address => bool) public supported_currencies;
    address public primary_stablecoin; // USDC or similar
    address public native_token; // ETH or chain native token
    
    // Oracle for exchange rates
    address public price_oracle;
    
    // Access control
    address public admin;
    address public claims_processor;
    address public treasury;
    mapping(address => bool) public settlement_operators;
    mapping(address => bool) public liquidity_providers;
    
    // Configuration
    u256 public processing_fee_rate; // Basis points (e.g., 50 = 0.5%)
    u256 public minimum_settlement_amount;
    u256 public maximum_settlement_amount;
    u256 public settlement_timeout; // Seconds
    bool public emergency_pause;
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyClaimsProcessor() {
        require(msg.sender == claims_processor, "Only claims processor can call this");
        _;
    }
    
    modifier onlySettlementOperator() {
        require(settlement_operators[msg.sender] || msg.sender == admin, "Only settlement operators can perform this action");
        _;
    }
    
    modifier onlyLiquidityProvider() {
        require(liquidity_providers[msg.sender] || msg.sender == admin, "Only liquidity providers can perform this action");
        _;
    }
    
    modifier notPaused() {
        require(!emergency_pause, "Contract is paused");
        _;
    }
    
    modifier validSettlement(u256 settlement_id) {
        require(settlements[settlement_id].id != 0, "Settlement does not exist");
        _;
    }
    
    // Constructor
    constructor(
        address _claims_processor,
        address _primary_stablecoin,
        address _price_oracle,
        address _treasury
    ) {
        admin = msg.sender;
        claims_processor = _claims_processor;
        primary_stablecoin = _primary_stablecoin;
        price_oracle = _price_oracle;
        treasury = _treasury;
        
        next_settlement_id = 1;
        next_batch_id = 1;
        processing_fee_rate = 50; // 0.5%
        minimum_settlement_amount = 100 * 10**18; // $100
        maximum_settlement_amount = 1000000 * 10**18; // $1M
        settlement_timeout = 3600; // 1 hour
        
        // Add supported currencies
        supported_currencies[_primary_stablecoin] = true;
        supported_currencies[address(0)] = true; // Native token
        
        // Set admin as initial operator and liquidity provider
        settlement_operators[admin] = true;
        liquidity_providers[admin] = true;
    }
    
    // Initiate settlement for approved claim
    function initiate_settlement(
        u256 claim_id,
        address provider,
        address patient,
        u256 gross_amount,
        u256 deductible,
        u256 copay
    ) public onlyClaimsProcessor notPaused returns (u256) {
        
        require(gross_amount > 0, "Settlement amount must be greater than 0");
        require(provider != address(0), "Invalid provider address");
        
        u256 net_amount = gross_amount - deductible - copay;
        require(net_amount > 0, "Net settlement amount must be greater than 0");
        require(net_amount >= minimum_settlement_amount, "Amount below minimum threshold");
        require(net_amount <= maximum_settlement_amount, "Amount exceeds maximum threshold");
        
        u256 settlement_id = next_settlement_id++;
        
        // Get provider preferences
        ProviderPreferences memory prefs = provider_preferences[provider];
        if (prefs.provider == address(0)) {
            // Set default preferences if not configured
            prefs = _get_default_preferences(provider);
        }
        
        // Calculate fees
        SettlementFees memory fees = _calculate_fees(net_amount, prefs.preferred_payment_method);
        
        // Get exchange rate if currency conversion needed
        u256 exchange_rate = _get_exchange_rate(primary_stablecoin, prefs.preferred_currency);
        
        settlements[settlement_id] = Settlement {
            id: settlement_id,
            claim_id: claim_id,
            provider: provider,
            patient: patient,
            gross_amount: gross_amount,
            deductible: deductible,
            copay: copay,
            net_amount: net_amount,
            currency: prefs.preferred_currency,
            payment_method: prefs.preferred_payment_method,
            status: SettlementStatus::Pending,
            initiated_at: block.timestamp,
            completed_at: Timestamp(0),
            transaction_hash: bytes32(0),
            gas_used: 0,
            exchange_rate: exchange_rate,
            fees: fees,
            reconciliation_data: ReconciliationData {
                batch_id: 0,
                reconciled: false,
                reconciliation_date: Timestamp(0),
                discrepancy_amount: 0,
                notes: ""
            }
        };
        
        provider_settlements[provider].push(settlement_id);
        total_settlements_processed++;
        
        emit SettlementInitiated(settlement_id, claim_id, provider, net_amount);
        
        // Process settlement based on preferences
        if (prefs.auto_settlement_enabled && prefs.settlement_frequency == SettlementFrequency::Immediate) {
            _process_immediate_settlement(settlement_id);
        } else {
            _queue_for_batch_settlement(settlement_id, provider);
        }
        
        return settlement_id;
    }
    
    // Process immediate settlement
    function _process_immediate_settlement(u256 settlement_id) internal {
        Settlement storage settlement = settlements[settlement_id];
        settlement.status = SettlementStatus::Processing;
        
        bool success = false;
        bytes32 tx_hash;
        
        if (settlement.payment_method == PaymentMethod::DirectTransfer) {
            (success, tx_hash) = _execute_direct_transfer(settlement_id);
        } else if (settlement.payment_method == PaymentMethod::StableCoin) {
            (success, tx_hash) = _execute_stablecoin_transfer(settlement_id);
        } else if (settlement.payment_method == PaymentMethod::DigitalWallet) {
            (success, tx_hash) = _execute_wallet_transfer(settlement_id);
        }
        
        if (success) {
            settlement.status = SettlementStatus::Completed;
            settlement.completed_at = block.timestamp;
            settlement.transaction_hash = tx_hash;
            total_volume_settled += settlement.net_amount;
            total_fees_collected += settlement.fees.total_fees;
            
            emit SettlementCompleted(settlement_id, settlement.provider, settlement.net_amount, tx_hash);
            
            // Send notification
            _send_settlement_notification(settlement_id);
        } else {
            settlement.status = SettlementStatus::Failed;
            emit SettlementFailed(settlement_id, "Transfer execution failed");
        }
    }
    
    // Execute direct transfer
    function _execute_direct_transfer(u256 settlement_id) internal returns (bool, bytes32) {
        Settlement memory settlement = settlements[settlement_id];
        
        // Check liquidity availability
        if (!_check_liquidity_availability(settlement.currency, settlement.net_amount)) {
            return (false, bytes32(0));
        }
        
        // Execute transfer
        if (settlement.currency == address(0)) {
            // Native token transfer
            (bool success, ) = payable(settlement.provider).call{value: settlement.net_amount}("");
            return (success, keccak256(abi.encodePacked(settlement_id, block.timestamp)));
        } else {
            // ERC20 token transfer
            ERC20 token = ERC20(settlement.currency);
            bool success = token.transfer(settlement.provider, settlement.net_amount);
            return (success, keccak256(abi.encodePacked(settlement_id, block.timestamp)));
        }
    }
    
    // Execute stablecoin transfer
    function _execute_stablecoin_transfer(u256 settlement_id) internal returns (bool, bytes32) {
        Settlement memory settlement = settlements[settlement_id];
        
        ERC20 stablecoin = ERC20(primary_stablecoin);
        
        // Convert amount if needed
        u256 transfer_amount = settlement.net_amount;
        if (settlement.currency != primary_stablecoin) {
            transfer_amount = (settlement.net_amount * settlement.exchange_rate) / 10**18;
        }
        
        bool success = stablecoin.transfer(settlement.provider, transfer_amount);
        return (success, keccak256(abi.encodePacked(settlement_id, block.timestamp)));
    }
    
    // Execute digital wallet transfer
    function _execute_wallet_transfer(u256 settlement_id) internal returns (bool, bytes32) {
        // This would integrate with external wallet APIs
        // For now, return success with mock transaction hash
        return (true, keccak256(abi.encodePacked(settlement_id, block.timestamp, "wallet_transfer")));
    }
    
    // Queue settlement for batch processing
    function _queue_for_batch_settlement(u256 settlement_id, address provider) internal {
        // Add to provider's pending settlements
        // Batch processing would be triggered based on frequency preferences
    }
    
    // Process batch settlement
    function process_batch_settlement(address provider) public onlySettlementOperator notPaused {
        Vec<u256> pending_settlements = _get_pending_settlements(provider);
        require(pending_settlements.length > 0, "No pending settlements for provider");
        
        u256 batch_id = next_batch_id++;
        u256 total_amount = 0;
        
        // Calculate total amount
        for (uint i = 0; i < pending_settlements.length; i++) {
            Settlement storage settlement = settlements[pending_settlements[i]];
            total_amount += settlement.net_amount;
            settlement.reconciliation_data.batch_id = batch_id;
        }
        
        // Create batch record
        settlement_batches[batch_id] = SettlementBatch {
            id: batch_id,
            provider: provider,
            settlement_ids: pending_settlements,
            total_amount: total_amount,
            batch_status: SettlementStatus::Processing,
            created_at: block.timestamp,
            processed_at: Timestamp(0),
            transaction_hash: bytes32(0)
        };
        
        // Execute batch transfer
        bool success = _execute_batch_transfer(batch_id);
        
        if (success) {
            settlement_batches[batch_id].batch_status = SettlementStatus::Completed;
            settlement_batches[batch_id].processed_at = block.timestamp;
            
            // Update individual settlement statuses
            for (uint i = 0; i < pending_settlements.length; i++) {
                settlements[pending_settlements[i]].status = SettlementStatus::Completed;
                settlements[pending_settlements[i]].completed_at = block.timestamp;
            }
            
            emit BatchSettlementProcessed(batch_id, provider, total_amount);
        } else {
            settlement_batches[batch_id].batch_status = SettlementStatus::Failed;
        }
    }
    
    // Execute batch transfer
    function _execute_batch_transfer(u256 batch_id) internal returns (bool) {
        SettlementBatch memory batch = settlement_batches[batch_id];
        ProviderPreferences memory prefs = provider_preferences[batch.provider];
        
        if (prefs.preferred_currency == address(0)) {
            // Native token transfer
            (bool success, ) = payable(batch.provider).call{value: batch.total_amount}("");
            return success;
        } else {
            // ERC20 token transfer
            ERC20 token = ERC20(prefs.preferred_currency);
            return token.transfer(batch.provider, batch.total_amount);
        }
    }
    
    // Get pending settlements for provider
    function _get_pending_settlements(address provider) internal view returns (Vec<u256> memory) {
        Vec<u256> pending;
        Vec<u256> memory provider_settlement_ids = provider_settlements[provider];
        
        for (uint i = 0; i < provider_settlement_ids.length; i++) {
            if (settlements[provider_settlement_ids[i]].status == SettlementStatus::Pending) {
                pending.push(provider_settlement_ids[i]);
            }
        }
        
        return pending;
    }
    
    // Calculate settlement fees
    function _calculate_fees(u256 amount, PaymentMethod method) internal view returns (SettlementFees memory) {
        u256 processing_fee = (amount * processing_fee_rate) / 10000;
        u256 network_fee = 0;
        u256 exchange_fee = 0;
        
        // Different fees for different payment methods
        if (method == PaymentMethod::BankTransfer) {
            network_fee = 5 * 10**18; // $5 flat fee
        } else if (method == PaymentMethod::DirectTransfer) {
            network_fee = tx.gasprice * 21000; // Estimated gas cost
        }
        
        u256 total_fees = processing_fee + network_fee + exchange_fee;
        
        return SettlementFees {
            processing_fee: processing_fee,
            network_fee: network_fee,
            exchange_fee: exchange_fee,
            total_fees: total_fees,
            fee_recipient: treasury
        };
    }
    
    // Get exchange rate between currencies
    function _get_exchange_rate(address from_currency, address to_currency) internal view returns (u256) {
        if (from_currency == to_currency) {
            return 10**18; // 1:1 ratio
        }
        
        // Get rate from oracle or stored rates
        u256 rate = exchange_rates[from_currency][to_currency];
        if (rate == 0) {
            rate = 10**18; // Default 1:1 if no rate available
        }
        
        return rate;
    }
    
    // Check liquidity availability
    function _check_liquidity_availability(address currency, u256 amount) internal view returns (bool) {
        LiquidityPool memory pool = liquidity_pools[currency];
        return pool.available_liquidity >= amount;
    }
    
    // Get default provider preferences
    function _get_default_preferences(address provider) internal view returns (ProviderPreferences memory) {
        return ProviderPreferences {
            provider: provider,
            preferred_currency: primary_stablecoin,
            preferred_payment_method: PaymentMethod::StableCoin,
            minimum_settlement_amount: minimum_settlement_amount,
            settlement_frequency: SettlementFrequency::Daily,
            bank_details: BankDetails {
                account_number: "",
                routing_number: "",
                bank_name: "",
                swift_code: "",
                account_holder_name: ""
            },
            auto_settlement_enabled: false,
            notification_preferences: NotificationPreferences {
                email_notifications: true,
                sms_notifications: false,
                webhook_url: "",
                notification_threshold: 1000 * 10**18
            }
        };
    }
    
    // Send settlement notification
    function _send_settlement_notification(u256 settlement_id) internal {
        // This would integrate with notification service
        // Email, SMS, webhook notifications
    }
    
    // Provider preference management
    function update_provider_preferences(
        address preferred_currency,
        PaymentMethod preferred_method,
        u256 min_settlement_amount,
        SettlementFrequency frequency,
        bool auto_settlement
    ) public {
        require(supported_currencies[preferred_currency], "Currency not supported");
        
        ProviderPreferences storage prefs = provider_preferences[msg.sender];
        prefs.provider = msg.sender;
        prefs.preferred_currency = preferred_currency;
        prefs.preferred_payment_method = preferred_method;
        prefs.minimum_settlement_amount = min_settlement_amount;
        prefs.settlement_frequency = frequency;
        prefs.auto_settlement_enabled = auto_settlement;
        
        emit ProviderPreferencesUpdated(msg.sender);
    }
    
    // Liquidity management
    function add_liquidity(address token, u256 amount) public onlyLiquidityProvider {
        require(supported_currencies[token], "Token not supported");
        require(amount > 0, "Amount must be greater than 0");
        
        if (token == address(0)) {
            require(msg.value == amount, "Incorrect ETH amount");
        } else {
            ERC20(token).transferFrom(msg.sender, address(this), amount);
        }
        
        LiquidityPool storage pool = liquidity_pools[token];
        pool.token = token;
        pool.total_liquidity += amount;
        pool.available_liquidity += amount;
        pool.last_rebalance = block.timestamp;
        
        emit LiquidityAdded(token, amount, msg.sender);
    }
    
    function remove_liquidity(address token, u256 amount) public onlyLiquidityProvider {
        LiquidityPool storage pool = liquidity_pools[token];
        require(pool.available_liquidity >= amount, "Insufficient liquidity");
        
        pool.total_liquidity -= amount;
        pool.available_liquidity -= amount;
        
        if (token == address(0)) {
            payable(msg.sender).transfer(amount);
        } else {
            ERC20(token).transfer(msg.sender, amount);
        }
        
        emit LiquidityRemoved(token, amount, msg.sender);
    }
    
    // Dispute management
    function raise_dispute(u256 settlement_id, string reason) public validSettlement(settlement_id) {
        Settlement storage settlement = settlements[settlement_id];
        require(msg.sender == settlement.provider || msg.sender == settlement.patient, "Only involved parties can raise disputes");
        require(settlement.status == SettlementStatus::Completed, "Can only dispute completed settlements");
        
        settlement.status = SettlementStatus::Disputed;
        emit DisputeRaised(settlement_id, msg.sender, reason);
    }
    
    // Administrative functions
    function add_supported_currency(address currency) public onlyAdmin {
        supported_currencies[currency] = true;
    }
    
    function update_exchange_rate(address from_currency, address to_currency, u256 rate) public onlyAdmin {
        exchange_rates[from_currency][to_currency] = rate;
        exchange_rates[to_currency][from_currency] = (10**36) / rate; // Inverse rate
        emit ExchangeRateUpdated(from_currency, to_currency, rate);
    }
    
    function set_processing_fee_rate(u256 rate) public onlyAdmin {
        require(rate <= 1000, "Fee rate cannot exceed 10%"); // 1000 basis points = 10%
        processing_fee_rate = rate;
    }
    
    function emergency_pause_toggle() public onlyAdmin {
        emergency_pause = !emergency_pause;
    }
    
    function add_settlement_operator(address operator) public onlyAdmin {
        settlement_operators[operator] = true;
    }
    
    function add_liquidity_provider(address provider) public onlyAdmin {
        liquidity_providers[provider] = true;
    }
    
    // View functions
    function get_settlement(u256 settlement_id) public view returns (Settlement memory) {
        return settlements[settlement_id];
    }
    
    function get_provider_preferences(address provider) public view returns (ProviderPreferences memory) {
        return provider_preferences[provider];
    }
    
    function get_settlement_batch(u256 batch_id) public view returns (SettlementBatch memory) {
        return settlement_batches[batch_id];
    }
    
    function get_liquidity_pool(address token) public view returns (LiquidityPool memory) {
        return liquidity_pools[token];
    }
    
    function get_provider_settlements(address provider) public view returns (Vec<u256> memory) {
        return provider_settlements[provider];
    }
    
    function get_contract_stats() public view returns (u256, u256, u256, u256) {
        return (total_settlements_processed, total_volume_settled, total_fees_collected, next_settlement_id - 1);
    }
    
    function get_pending_settlement_count(address provider) public view returns (u256) {
        return _get_pending_settlements(provider).length;
    }
    
    // Emergency functions
    function emergency_withdraw(address token, u256 amount) public onlyAdmin {
        require(emergency_pause, "Can only withdraw during emergency pause");
        
        if (token == address(0)) {
            payable(admin).transfer(amount);
        } else {
            ERC20(token).transfer(admin, amount);
        }
    }
    
    // Receive function for ETH deposits
    receive() external payable {
        // Add to native token liquidity pool
        LiquidityPool storage pool = liquidity_pools[address(0)];
        pool.total_liquidity += msg.value;
        pool.available_liquidity += msg.value;
    }
}