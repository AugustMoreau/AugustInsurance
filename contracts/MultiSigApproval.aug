// SPDX-License-Identifier: MIT
// AugustInsurance Multi-Signature Approval Smart Contract
// Governance system for large claims requiring multiple approvals

use std::collections::HashMap;
use std::time::Timestamp;
use std::events::Event;
use std::access::AccessControl;

// Approval status enumeration
enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Executed
}

// Approver roles
enum ApproverRole {
    MedicalDirector,
    FinancialController,
    RiskManager,
    ComplianceOfficer,
    ChiefMedicalOfficer,
    ActuarialAnalyst,
    LegalCounsel,
    ExecutiveApprover
}

// Approval request structure
struct ApprovalRequest {
    id: u256,
    claim_id: u256,
    requester: address,
    amount: u256,
    description: string,
    medical_justification: string,
    risk_assessment: string,
    urgency_level: UrgencyLevel,
    required_approvals: Vec<ApproverRole>,
    received_approvals: Vec<Approval>,
    rejection_count: u8,
    status: ApprovalStatus,
    created_at: Timestamp,
    deadline: Timestamp,
    executed_at: Timestamp,
    execution_hash: bytes32
}

// Individual approval structure
struct Approval {
    approver: address,
    role: ApproverRole,
    decision: bool, // true = approve, false = reject
    comments: string,
    timestamp: Timestamp,
    signature: bytes
}

// Urgency levels
enum UrgencyLevel {
    Standard,   // 7 days
    High,       // 3 days
    Critical,   // 24 hours
    Emergency   // 6 hours
}

// Approver information
struct Approver {
    wallet_address: address,
    role: ApproverRole,
    name: string,
    department: string,
    is_active: bool,
    approval_limit: u256,
    total_approvals: u256,
    total_rejections: u256,
    last_activity: Timestamp,
    backup_approver: address
}

// Approval policy configuration
struct ApprovalPolicy {
    min_approvals_required: u8,
    max_rejections_allowed: u8,
    approval_timeout_hours: u256,
    amount_thresholds: HashMap<u256, Vec<ApproverRole>>,
    emergency_override_roles: Vec<ApproverRole>,
    sequential_approval_required: bool
}

// Events
event ApprovalRequestCreated(request_id: u256, claim_id: u256, amount: u256, urgency: UrgencyLevel);
event ApprovalReceived(request_id: u256, approver: address, role: ApproverRole, decision: bool);
event ApprovalRequestApproved(request_id: u256, claim_id: u256, final_approver: address);
event ApprovalRequestRejected(request_id: u256, claim_id: u256, reason: string);
event ApprovalRequestExpired(request_id: u256, claim_id: u256);
event EmergencyOverrideUsed(request_id: u256, override_by: address, reason: string);
event ApproverAdded(approver: address, role: ApproverRole);
event ApproverRemoved(approver: address, role: ApproverRole);
event PolicyUpdated(policy_type: string, updated_by: address);

contract MultiSigApproval {
    // State variables
    mapping(u256 => ApprovalRequest) public approval_requests;
    mapping(address => Approver) public approvers;
    mapping(ApproverRole => Vec<address>) public role_approvers;
    mapping(u256 => bool) public executed_requests;
    
    ApprovalPolicy public current_policy;
    u256 public next_request_id;
    u256 public total_requests;
    u256 public total_approved;
    u256 public total_rejected;
    
    // Access control
    address public admin;
    address public claims_processor;
    mapping(address => bool) public policy_managers;
    mapping(address => bool) public emergency_overrides;
    
    // Constants
    u256 constant LARGE_CLAIM_THRESHOLD = 50000 * 10**18; // $50,000
    u256 constant CRITICAL_CLAIM_THRESHOLD = 250000 * 10**18; // $250,000
    u256 constant EMERGENCY_CLAIM_THRESHOLD = 1000000 * 10**18; // $1,000,000
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyClaimsProcessor() {
        require(msg.sender == claims_processor, "Only claims processor can call this");
        _;
    }
    
    modifier onlyApprover() {
        require(approvers[msg.sender].is_active, "Only active approvers can perform this action");
        _;
    }
    
    modifier onlyPolicyManager() {
        require(policy_managers[msg.sender] || msg.sender == admin, "Only policy managers can perform this action");
        _;
    }
    
    modifier validRequest(u256 request_id) {
        require(approval_requests[request_id].id != 0, "Request does not exist");
        require(approval_requests[request_id].status == ApprovalStatus::Pending, "Request is not pending");
        _;
    }
    
    modifier notExpired(u256 request_id) {
        require(block.timestamp <= approval_requests[request_id].deadline, "Request has expired");
        _;
    }
    
    // Constructor
    constructor(address _claims_processor) {
        admin = msg.sender;
        claims_processor = _claims_processor;
        next_request_id = 1;
        
        // Initialize default approval policy
        _initialize_default_policy();
        
        // Set admin as initial policy manager and emergency override
        policy_managers[admin] = true;
        emergency_overrides[admin] = true;
    }
    
    // Create approval request
    function create_approval_request(
        u256 claim_id,
        u256 amount,
        string description,
        string medical_justification,
        string risk_assessment,
        UrgencyLevel urgency_level
    ) public onlyClaimsProcessor returns (u256) {
        
        require(amount >= LARGE_CLAIM_THRESHOLD, "Amount does not require multi-sig approval");
        
        u256 request_id = next_request_id++;
        
        // Determine required approvers based on amount and urgency
        Vec<ApproverRole> required_roles = _determine_required_approvers(amount, urgency_level);
        
        // Calculate deadline based on urgency
        u256 deadline_hours = _get_deadline_hours(urgency_level);
        Timestamp deadline = block.timestamp + (deadline_hours * 3600);
        
        approval_requests[request_id] = ApprovalRequest {
            id: request_id,
            claim_id: claim_id,
            requester: msg.sender,
            amount: amount,
            description: description,
            medical_justification: medical_justification,
            risk_assessment: risk_assessment,
            urgency_level: urgency_level,
            required_approvals: required_roles,
            received_approvals: Vec<Approval>(),
            rejection_count: 0,
            status: ApprovalStatus::Pending,
            created_at: block.timestamp,
            deadline: deadline,
            executed_at: Timestamp(0),
            execution_hash: bytes32(0)
        };
        
        total_requests++;
        
        emit ApprovalRequestCreated(request_id, claim_id, amount, urgency_level);
        
        // Notify required approvers (would integrate with notification system)
        _notify_approvers(request_id, required_roles);
        
        return request_id;
    }
    
    // Submit approval or rejection
    function submit_approval(
        u256 request_id,
        bool decision,
        string comments,
        bytes signature
    ) public onlyApprover validRequest(request_id) notExpired(request_id) {
        
        ApprovalRequest storage request = approval_requests[request_id];
        Approver memory approver = approvers[msg.sender];
        
        // Check if approver is required for this request
        bool is_required = false;
        for (uint i = 0; i < request.required_approvals.length; i++) {
            if (request.required_approvals[i] == approver.role) {
                is_required = true;
                break;
            }
        }
        require(is_required, "Approver role not required for this request");
        
        // Check if approver already submitted decision
        for (uint i = 0; i < request.received_approvals.length; i++) {
            require(request.received_approvals[i].approver != msg.sender, "Approver already submitted decision");
        }
        
        // Check approval limit
        require(request.amount <= approver.approval_limit, "Amount exceeds approver's limit");
        
        // Create approval record
        Approval memory approval = Approval {
            approver: msg.sender,
            role: approver.role,
            decision: decision,
            comments: comments,
            timestamp: block.timestamp,
            signature: signature
        };
        
        request.received_approvals.push(approval);
        
        // Update approver statistics
        if (decision) {
            approvers[msg.sender].total_approvals++;
        } else {
            approvers[msg.sender].total_rejections++;
            request.rejection_count++;
        }
        approvers[msg.sender].last_activity = block.timestamp;
        
        emit ApprovalReceived(request_id, msg.sender, approver.role, decision);
        
        // Check if request should be approved or rejected
        _evaluate_request_status(request_id);
    }
    
    // Emergency override function
    function emergency_override(
        u256 request_id,
        string reason,
        bytes signature
    ) public validRequest(request_id) {
        require(emergency_overrides[msg.sender], "Not authorized for emergency override");
        
        ApprovalRequest storage request = approval_requests[request_id];
        require(request.urgency_level == UrgencyLevel::Emergency, "Emergency override only for emergency requests");
        
        // Create override approval
        Approval memory override_approval = Approval {
            approver: msg.sender,
            role: ApproverRole::ExecutiveApprover,
            decision: true,
            comments: string("EMERGENCY OVERRIDE: ").concat(reason),
            timestamp: block.timestamp,
            signature: signature
        };
        
        request.received_approvals.push(override_approval);
        request.status = ApprovalStatus::Approved;
        total_approved++;
        
        emit EmergencyOverrideUsed(request_id, msg.sender, reason);
        emit ApprovalRequestApproved(request_id, request.claim_id, msg.sender);
    }
    
    // Evaluate request status after each approval/rejection
    function _evaluate_request_status(u256 request_id) internal {
        ApprovalRequest storage request = approval_requests[request_id];
        
        // Check if too many rejections
        if (request.rejection_count > current_policy.max_rejections_allowed) {
            request.status = ApprovalStatus::Rejected;
            total_rejected++;
            emit ApprovalRequestRejected(request_id, request.claim_id, "Too many rejections");
            return;
        }
        
        // Count approvals by role
        HashMap<ApproverRole, bool> role_approvals;
        u8 approval_count = 0;
        
        for (uint i = 0; i < request.received_approvals.length; i++) {
            Approval memory approval = request.received_approvals[i];
            if (approval.decision) {
                role_approvals[approval.role] = true;
                approval_count++;
            }
        }
        
        // Check if all required roles have approved
        bool all_roles_approved = true;
        for (uint i = 0; i < request.required_approvals.length; i++) {
            if (!role_approvals[request.required_approvals[i]]) {
                all_roles_approved = false;
                break;
            }
        }
        
        // Approve if minimum requirements met
        if (all_roles_approved && approval_count >= current_policy.min_approvals_required) {
            request.status = ApprovalStatus::Approved;
            total_approved++;
            emit ApprovalRequestApproved(request_id, request.claim_id, msg.sender);
        }
    }
    
    // Determine required approvers based on amount and urgency
    function _determine_required_approvers(u256 amount, UrgencyLevel urgency) internal pure returns (Vec<ApproverRole>) {
        Vec<ApproverRole> required_roles;
        
        // Base requirements
        required_roles.push(ApproverRole::MedicalDirector);
        required_roles.push(ApproverRole::FinancialController);
        
        // Amount-based requirements
        if (amount >= EMERGENCY_CLAIM_THRESHOLD) {
            required_roles.push(ApproverRole::ChiefMedicalOfficer);
            required_roles.push(ApproverRole::ExecutiveApprover);
            required_roles.push(ApproverRole::LegalCounsel);
        } else if (amount >= CRITICAL_CLAIM_THRESHOLD) {
            required_roles.push(ApproverRole::RiskManager);
            required_roles.push(ApproverRole::ActuarialAnalyst);
        }
        
        // Urgency-based requirements
        if (urgency == UrgencyLevel::Emergency || urgency == UrgencyLevel::Critical) {
            required_roles.push(ApproverRole::ComplianceOfficer);
        }
        
        return required_roles;
    }
    
    // Get deadline hours based on urgency
    function _get_deadline_hours(UrgencyLevel urgency) internal view returns (u256) {
        if (urgency == UrgencyLevel::Emergency) return 6;
        if (urgency == UrgencyLevel::Critical) return 24;
        if (urgency == UrgencyLevel::High) return 72;
        return 168; // 7 days for standard
    }
    
    // Initialize default approval policy
    function _initialize_default_policy() internal {
        current_policy = ApprovalPolicy {
            min_approvals_required: 2,
            max_rejections_allowed: 1,
            approval_timeout_hours: 168, // 7 days
            amount_thresholds: HashMap<u256, Vec<ApproverRole>>(),
            emergency_override_roles: Vec<ApproverRole>(),
            sequential_approval_required: false
        };
        
        // Set emergency override roles
        current_policy.emergency_override_roles.push(ApproverRole::ChiefMedicalOfficer);
        current_policy.emergency_override_roles.push(ApproverRole::ExecutiveApprover);
    }
    
    // Notify approvers (placeholder for notification system integration)
    function _notify_approvers(u256 request_id, Vec<ApproverRole> required_roles) internal {
        // This would integrate with external notification system
        // Email, SMS, push notifications, etc.
    }
    
    // Check for expired requests
    function check_expired_requests() public {
        // This function would be called periodically to mark expired requests
        // In a real implementation, this might be automated with a cron job or oracle
    }
    
    // Mark specific request as expired
    function mark_expired(u256 request_id) public validRequest(request_id) {
        ApprovalRequest storage request = approval_requests[request_id];
        require(block.timestamp > request.deadline, "Request has not expired yet");
        
        request.status = ApprovalStatus::Expired;
        emit ApprovalRequestExpired(request_id, request.claim_id);
    }
    
    // Execute approved request
    function execute_approval(u256 request_id) public onlyClaimsProcessor returns (bool) {
        ApprovalRequest storage request = approval_requests[request_id];
        require(request.status == ApprovalStatus::Approved, "Request is not approved");
        require(!executed_requests[request_id], "Request already executed");
        
        executed_requests[request_id] = true;
        request.status = ApprovalStatus::Executed;
        request.executed_at = block.timestamp;
        request.execution_hash = keccak256(abi.encodePacked(request_id, block.timestamp, msg.sender));
        
        return true;
    }
    
    // Administrative functions
    function add_approver(
        address approver_address,
        ApproverRole role,
        string name,
        string department,
        u256 approval_limit
    ) public onlyAdmin {
        require(approver_address != address(0), "Invalid approver address");
        require(!approvers[approver_address].is_active, "Approver already exists");
        
        approvers[approver_address] = Approver {
            wallet_address: approver_address,
            role: role,
            name: name,
            department: department,
            is_active: true,
            approval_limit: approval_limit,
            total_approvals: 0,
            total_rejections: 0,
            last_activity: block.timestamp,
            backup_approver: address(0)
        };
        
        role_approvers[role].push(approver_address);
        
        emit ApproverAdded(approver_address, role);
    }
    
    function remove_approver(address approver_address) public onlyAdmin {
        require(approvers[approver_address].is_active, "Approver does not exist");
        
        ApproverRole role = approvers[approver_address].role;
        approvers[approver_address].is_active = false;
        
        // Remove from role list
        Vec<address> storage role_list = role_approvers[role];
        for (uint i = 0; i < role_list.length; i++) {
            if (role_list[i] == approver_address) {
                role_list[i] = role_list[role_list.length - 1];
                role_list.pop();
                break;
            }
        }
        
        emit ApproverRemoved(approver_address, role);
    }
    
    function update_approval_policy(
        u8 min_approvals,
        u8 max_rejections,
        u256 timeout_hours
    ) public onlyPolicyManager {
        require(min_approvals > 0, "Minimum approvals must be greater than 0");
        require(max_rejections >= 0, "Max rejections cannot be negative");
        require(timeout_hours > 0, "Timeout must be greater than 0");
        
        current_policy.min_approvals_required = min_approvals;
        current_policy.max_rejections_allowed = max_rejections;
        current_policy.approval_timeout_hours = timeout_hours;
        
        emit PolicyUpdated("approval_policy", msg.sender);
    }
    
    function set_backup_approver(address backup) public onlyApprover {
        approvers[msg.sender].backup_approver = backup;
    }
    
    function add_policy_manager(address manager) public onlyAdmin {
        policy_managers[manager] = true;
    }
    
    function add_emergency_override(address override_address) public onlyAdmin {
        emergency_overrides[override_address] = true;
    }
    
    // View functions
    function get_approval_request(u256 request_id) public view returns (ApprovalRequest memory) {
        return approval_requests[request_id];
    }
    
    function get_approver(address approver_address) public view returns (Approver memory) {
        return approvers[approver_address];
    }
    
    function get_role_approvers(ApproverRole role) public view returns (Vec<address> memory) {
        return role_approvers[role];
    }
    
    function get_approval_policy() public view returns (ApprovalPolicy memory) {
        return current_policy;
    }
    
    function get_request_status(u256 request_id) public view returns (ApprovalStatus) {
        return approval_requests[request_id].status;
    }
    
    function is_request_approved(u256 request_id) public view returns (bool) {
        return approval_requests[request_id].status == ApprovalStatus::Approved;
    }
    
    function get_contract_stats() public view returns (u256, u256, u256, u256) {
        return (total_requests, total_approved, total_rejected, next_request_id - 1);
    }
    
    // Pending requests for an approver
    function get_pending_requests_for_approver(address approver_address) public view returns (Vec<u256> memory) {
        Vec<u256> pending_requests;
        ApproverRole approver_role = approvers[approver_address].role;
        
        for (u256 i = 1; i < next_request_id; i++) {
            ApprovalRequest memory request = approval_requests[i];
            if (request.status == ApprovalStatus::Pending && block.timestamp <= request.deadline) {
                // Check if approver's role is required
                for (uint j = 0; j < request.required_approvals.length; j++) {
                    if (request.required_approvals[j] == approver_role) {
                        // Check if approver hasn't already submitted
                        bool already_submitted = false;
                        for (uint k = 0; k < request.received_approvals.length; k++) {
                            if (request.received_approvals[k].approver == approver_address) {
                                already_submitted = true;
                                break;
                            }
                        }
                        if (!already_submitted) {
                            pending_requests.push(i);
                        }
                        break;
                    }
                }
            }
        }
        
        return pending_requests;
    }
}