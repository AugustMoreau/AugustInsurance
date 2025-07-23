// SPDX-License-Identifier: MIT
// AugustInsurance Claims Processing Smart Contract
// Professional-grade health insurance claims automation

use std::collections::HashMap;
use std::time::Timestamp;
use std::crypto::Hash;
use std::access::AccessControl;
use std::events::Event;
use std::math::SafeMath;

// Claim status enumeration
enum ClaimStatus {
    Submitted,
    UnderReview,
    Approved,
    Rejected,
    Settled,
    Disputed
}

// Claim priority levels
enum Priority {
    Low,
    Medium,
    High,
    Emergency
}

// Medical procedure categories
enum ProcedureCategory {
    Consultation,
    Diagnostic,
    Surgery,
    Emergency,
    Preventive,
    Specialist
}

// Claim data structure
struct Claim {
    id: u256,
    policy_holder: address,
    provider: address,
    amount: u256,
    procedure_code: string,
    procedure_category: ProcedureCategory,
    diagnosis_code: string,
    treatment_date: Timestamp,
    submission_date: Timestamp,
    status: ClaimStatus,
    priority: Priority,
    documents_hash: Hash,
    pre_auth_required: bool,
    pre_auth_number: string,
    estimated_cost: u256,
    approved_amount: u256,
    reviewer: address,
    review_notes: string,
    fraud_score: u8, // 0-100, higher = more suspicious
    settlement_date: Timestamp,
    is_emergency: bool
}

// Policy information
struct Policy {
    holder: address,
    premium_paid: u256,
    coverage_limit: u256,
    deductible: u256,
    copay_percentage: u8,
    is_active: bool,
    expiry_date: Timestamp,
    coverage_types: Vec<ProcedureCategory>
}

// Provider information
struct Provider {
    provider_address: address,
    name: string,
    license_number: string,
    specialty: string,
    is_verified: bool,
    reputation_score: u8,
    settlement_address: address
}

// Events
event ClaimSubmitted(claim_id: u256, policy_holder: address, amount: u256);
event ClaimApproved(claim_id: u256, approved_amount: u256, reviewer: address);
event ClaimRejected(claim_id: u256, reason: string, reviewer: address);
event ClaimSettled(claim_id: u256, amount: u256, provider: address);
event FraudDetected(claim_id: u256, fraud_score: u8, flags: Vec<string>);
event PolicyUpdated(policy_holder: address, coverage_limit: u256);
event ProviderRegistered(provider: address, name: string);

contract ClaimsProcessor {
    // State variables
    mapping(u256 => Claim) public claims;
    mapping(address => Policy) public policies;
    mapping(address => Provider) public providers;
    mapping(u256 => Vec<string>) public claim_documents;
    mapping(address => Vec<u256>) public user_claims;
    mapping(address => u256) public provider_balances;
    
    u256 public next_claim_id;
    u256 public total_claims_processed;
    u256 public total_amount_settled;
    u256 public fraud_detection_threshold; // Default: 75
    
    // Access control
    address public admin;
    mapping(address => bool) public reviewers;
    mapping(address => bool) public fraud_analysts;
    
    // Contract addresses for external services
    address public fraud_detector_contract;
    address public multi_sig_contract;
    address public settlement_engine;
    
    // Constants
    u256 constant LARGE_CLAIM_THRESHOLD = 50000 * 10**18; // $50,000 in wei
    u256 constant EMERGENCY_PROCESSING_TIME = 3600; // 1 hour in seconds
    u256 constant STANDARD_PROCESSING_TIME = 86400 * 3; // 3 days
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyReviewer() {
        require(reviewers[msg.sender] || msg.sender == admin, "Only reviewers can perform this action");
        _;
    }
    
    modifier onlyFraudAnalyst() {
        require(fraud_analysts[msg.sender] || msg.sender == admin, "Only fraud analysts can perform this action");
        _;
    }
    
    modifier validClaim(u256 claim_id) {
        require(claims[claim_id].id != 0, "Claim does not exist");
        _;
    }
    
    modifier onlyPolicyHolder(u256 claim_id) {
        require(claims[claim_id].policy_holder == msg.sender, "Only policy holder can perform this action");
        _;
    }
    
    // Constructor
    constructor(
        address _fraud_detector,
        address _multi_sig,
        address _settlement_engine
    ) {
        admin = msg.sender;
        fraud_detector_contract = _fraud_detector;
        multi_sig_contract = _multi_sig;
        settlement_engine = _settlement_engine;
        next_claim_id = 1;
        fraud_detection_threshold = 75;
        
        // Set admin as initial reviewer and fraud analyst
        reviewers[admin] = true;
        fraud_analysts[admin] = true;
    }
    
    // Policy management functions
    function register_policy(
        address policy_holder,
        u256 coverage_limit,
        u256 deductible,
        u8 copay_percentage,
        Timestamp expiry_date,
        Vec<ProcedureCategory> coverage_types
    ) public onlyAdmin {
        require(coverage_limit > 0, "Coverage limit must be greater than 0");
        require(copay_percentage <= 100, "Copay percentage cannot exceed 100%");
        
        policies[policy_holder] = Policy {
            holder: policy_holder,
            premium_paid: 0,
            coverage_limit: coverage_limit,
            deductible: deductible,
            copay_percentage: copay_percentage,
            is_active: true,
            expiry_date: expiry_date,
            coverage_types: coverage_types
        };
        
        emit PolicyUpdated(policy_holder, coverage_limit);
    }
    
    // Provider registration
    function register_provider(
        address provider_address,
        string name,
        string license_number,
        string specialty,
        address settlement_address
    ) public onlyAdmin {
        require(bytes(name).length > 0, "Provider name cannot be empty");
        require(bytes(license_number).length > 0, "License number cannot be empty");
        
        providers[provider_address] = Provider {
            provider_address: provider_address,
            name: name,
            license_number: license_number,
            specialty: specialty,
            is_verified: true,
            reputation_score: 100,
            settlement_address: settlement_address
        };
        
        emit ProviderRegistered(provider_address, name);
    }
    
    // Main claim submission function
    function submit_claim(
        address provider,
        u256 amount,
        string procedure_code,
        ProcedureCategory procedure_category,
        string diagnosis_code,
        Timestamp treatment_date,
        Hash documents_hash,
        bool pre_auth_required,
        string pre_auth_number,
        bool is_emergency
    ) public returns (u256) {
        // Validate policy
        Policy memory policy = policies[msg.sender];
        require(policy.is_active, "Policy is not active");
        require(block.timestamp <= policy.expiry_date, "Policy has expired");
        require(amount > 0, "Claim amount must be greater than 0");
        require(providers[provider].is_verified, "Provider is not verified");
        
        // Check coverage
        bool is_covered = false;
        for (uint i = 0; i < policy.coverage_types.length; i++) {
            if (policy.coverage_types[i] == procedure_category) {
                is_covered = true;
                break;
            }
        }
        require(is_covered, "Procedure not covered by policy");
        
        // Create claim
        u256 claim_id = next_claim_id++;
        Priority priority = is_emergency ? Priority::Emergency : Priority::Medium;
        
        claims[claim_id] = Claim {
            id: claim_id,
            policy_holder: msg.sender,
            provider: provider,
            amount: amount,
            procedure_code: procedure_code,
            procedure_category: procedure_category,
            diagnosis_code: diagnosis_code,
            treatment_date: treatment_date,
            submission_date: block.timestamp,
            status: ClaimStatus::Submitted,
            priority: priority,
            documents_hash: documents_hash,
            pre_auth_required: pre_auth_required,
            pre_auth_number: pre_auth_number,
            estimated_cost: amount,
            approved_amount: 0,
            reviewer: address(0),
            review_notes: "",
            fraud_score: 0,
            settlement_date: Timestamp(0),
            is_emergency: is_emergency
        };
        
        user_claims[msg.sender].push(claim_id);
        total_claims_processed++;
        
        // Trigger fraud detection
        _trigger_fraud_detection(claim_id);
        
        // Auto-approve small, low-risk claims
        if (amount < 1000 * 10**18 && !is_emergency) { // Less than $1000
            _auto_approve_claim(claim_id);
        }
        
        emit ClaimSubmitted(claim_id, msg.sender, amount);
        return claim_id;
    }
    
    // Claim review function
    function review_claim(
        u256 claim_id,
        bool approve,
        u256 approved_amount,
        string review_notes
    ) public onlyReviewer validClaim(claim_id) {
        Claim storage claim = claims[claim_id];
        require(claim.status == ClaimStatus::Submitted || claim.status == ClaimStatus::UnderReview, "Claim cannot be reviewed");
        
        claim.reviewer = msg.sender;
        claim.review_notes = review_notes;
        
        if (approve) {
            require(approved_amount > 0, "Approved amount must be greater than 0");
            require(approved_amount <= claim.amount, "Approved amount cannot exceed claim amount");
            
            claim.approved_amount = approved_amount;
            claim.status = ClaimStatus::Approved;
            
            // Check if large claim requires multi-sig approval
            if (approved_amount >= LARGE_CLAIM_THRESHOLD) {
                _require_multi_sig_approval(claim_id);
            } else {
                _process_settlement(claim_id);
            }
            
            emit ClaimApproved(claim_id, approved_amount, msg.sender);
        } else {
            claim.status = ClaimStatus::Rejected;
            emit ClaimRejected(claim_id, review_notes, msg.sender);
        }
    }
    
    // Settlement processing
    function process_settlement(u256 claim_id) public validClaim(claim_id) {
        Claim storage claim = claims[claim_id];
        require(claim.status == ClaimStatus::Approved, "Claim must be approved first");
        require(msg.sender == settlement_engine || msg.sender == admin, "Only settlement engine can process settlements");
        
        _process_settlement(claim_id);
    }
    
    // Internal settlement function
    function _process_settlement(u256 claim_id) internal {
        Claim storage claim = claims[claim_id];
        Policy memory policy = policies[claim.policy_holder];
        
        // Calculate final settlement amount after deductible and copay
        u256 after_deductible = claim.approved_amount > policy.deductible ? 
            claim.approved_amount - policy.deductible : 0;
        
        u256 copay_amount = (after_deductible * policy.copay_percentage) / 100;
        u256 settlement_amount = after_deductible - copay_amount;
        
        // Transfer to provider
        Provider memory provider = providers[claim.provider];
        provider_balances[provider.settlement_address] += settlement_amount;
        
        claim.status = ClaimStatus::Settled;
        claim.settlement_date = block.timestamp;
        total_amount_settled += settlement_amount;
        
        emit ClaimSettled(claim_id, settlement_amount, claim.provider);
    }
    
    // Fraud detection integration
    function _trigger_fraud_detection(u256 claim_id) internal {
        // This would integrate with external fraud detection service
        // For now, we'll implement basic pattern matching
        Claim storage claim = claims[claim_id];
        
        u8 fraud_score = _calculate_fraud_score(claim_id);
        claim.fraud_score = fraud_score;
        
        if (fraud_score >= fraud_detection_threshold) {
            claim.status = ClaimStatus::UnderReview;
            Vec<string> flags;
            flags.push("High fraud score detected");
            emit FraudDetected(claim_id, fraud_score, flags);
        }
    }
    
    // Basic fraud scoring algorithm
    function _calculate_fraud_score(u256 claim_id) internal view returns (u8) {
        Claim memory claim = claims[claim_id];
        u8 score = 0;
        
        // Check for unusual amounts
        if (claim.amount > 100000 * 10**18) { // > $100,000
            score += 30;
        }
        
        // Check submission timing (weekend/holiday submissions are suspicious)
        if (_is_weekend_or_holiday(claim.submission_date)) {
            score += 15;
        }
        
        // Check provider reputation
        Provider memory provider = providers[claim.provider];
        if (provider.reputation_score < 70) {
            score += 25;
        }
        
        // Check for duplicate claims
        if (_has_duplicate_claims(claim.policy_holder, claim.procedure_code, claim.treatment_date)) {
            score += 40;
        }
        
        return score > 100 ? 100 : score;
    }
    
    // Auto-approval for small claims
    function _auto_approve_claim(u256 claim_id) internal {
        Claim storage claim = claims[claim_id];
        claim.status = ClaimStatus::Approved;
        claim.approved_amount = claim.amount;
        claim.reviewer = address(this); // Contract auto-approval
        claim.review_notes = "Auto-approved: Low risk, small amount";
        
        _process_settlement(claim_id);
        emit ClaimApproved(claim_id, claim.amount, address(this));
    }
    
    // Multi-signature approval requirement
    function _require_multi_sig_approval(u256 claim_id) internal {
        // Integration with multi-sig contract for large claims
        // This would trigger the multi-sig approval process
        claims[claim_id].status = ClaimStatus::UnderReview;
    }
    
    // Utility functions
    function _is_weekend_or_holiday(Timestamp timestamp) internal pure returns (bool) {
        // Simplified weekend check (would need proper calendar integration)
        u256 day_of_week = (timestamp / 86400 + 4) % 7; // Thursday = 0
        return day_of_week == 5 || day_of_week == 6; // Saturday or Sunday
    }
    
    function _has_duplicate_claims(
        address policy_holder,
        string procedure_code,
        Timestamp treatment_date
    ) internal view returns (bool) {
        Vec<u256> memory user_claim_ids = user_claims[policy_holder];
        
        for (uint i = 0; i < user_claim_ids.length; i++) {
            Claim memory existing_claim = claims[user_claim_ids[i]];
            if (keccak256(bytes(existing_claim.procedure_code)) == keccak256(bytes(procedure_code)) &&
                existing_claim.treatment_date == treatment_date &&
                existing_claim.status != ClaimStatus::Rejected) {
                return true;
            }
        }
        return false;
    }
    
    // Administrative functions
    function add_reviewer(address reviewer) public onlyAdmin {
        reviewers[reviewer] = true;
    }
    
    function remove_reviewer(address reviewer) public onlyAdmin {
        reviewers[reviewer] = false;
    }
    
    function add_fraud_analyst(address analyst) public onlyAdmin {
        fraud_analysts[analyst] = true;
    }
    
    function set_fraud_threshold(u256 threshold) public onlyAdmin {
        require(threshold <= 100, "Threshold cannot exceed 100");
        fraud_detection_threshold = threshold;
    }
    
    // Provider withdrawal function
    function withdraw_settlement(u256 amount) public {
        require(providers[msg.sender].is_verified, "Only verified providers can withdraw");
        require(provider_balances[msg.sender] >= amount, "Insufficient balance");
        
        provider_balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // View functions
    function get_claim(u256 claim_id) public view returns (Claim memory) {
        return claims[claim_id];
    }
    
    function get_user_claims(address user) public view returns (Vec<u256> memory) {
        return user_claims[user];
    }
    
    function get_policy(address policy_holder) public view returns (Policy memory) {
        return policies[policy_holder];
    }
    
    function get_provider(address provider) public view returns (Provider memory) {
        return providers[provider];
    }
    
    function get_contract_stats() public view returns (
        u256 total_claims,
        u256 total_settled,
        u256 next_id
    ) {
        return (total_claims_processed, total_amount_settled, next_claim_id);
    }
    
    // Emergency functions
    function emergency_pause() public onlyAdmin {
        // Implementation for emergency pause functionality
    }
    
    function emergency_resume() public onlyAdmin {
        // Implementation for emergency resume functionality
    }
}