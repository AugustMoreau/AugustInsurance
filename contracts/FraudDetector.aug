// SPDX-License-Identifier: MIT
// AugustInsurance Fraud Detection Smart Contract
// Advanced pattern analysis and anomaly detection for insurance claims

use std::collections::HashMap;
use std::time::Timestamp;
use std::math::SafeMath;
use std::crypto::Hash;
use std::ml::NeuralNetwork;
use std::events::Event;

// Fraud detection result structure
struct FraudAnalysis {
    claim_id: u256,
    overall_score: u8, // 0-100, higher = more suspicious
    risk_level: RiskLevel,
    detected_patterns: Vec<FraudPattern>,
    confidence: u8, // 0-100, confidence in the analysis
    analysis_timestamp: Timestamp,
    analyst: address,
    requires_manual_review: bool,
    ml_model_version: string
}

// Risk levels
enum RiskLevel {
    Low,      // 0-25
    Medium,   // 26-50
    High,     // 51-75
    Critical  // 76-100
}

// Fraud pattern types
enum FraudPattern {
    UnusualAmount,
    FrequencyAnomaly,
    ProviderCollusion,
    DocumentForgery,
    IdentityTheft,
    StagedAccident,
    ExaggeratedClaim,
    DuplicateClaim,
    TimingAnomaly,
    GeographicAnomaly,
    ProcedureStacking,
    BillingIrregularity
}

// Provider behavior tracking
struct ProviderBehavior {
    provider: address,
    total_claims: u256,
    total_amount: u256,
    average_claim_amount: u256,
    rejection_rate: u8,
    fraud_incidents: u256,
    last_audit_date: Timestamp,
    risk_score: u8,
    specialization_codes: Vec<string>,
    geographic_regions: Vec<string>
}

// Patient behavior tracking
struct PatientBehavior {
    patient: address,
    claim_frequency: u256,
    average_claim_amount: u256,
    provider_diversity: u256, // Number of different providers used
    procedure_diversity: u256, // Number of different procedures
    geographic_spread: u256, // Number of different locations
    last_claim_date: Timestamp,
    suspicious_patterns: Vec<FraudPattern>,
    risk_score: u8
}

// ML model parameters
struct MLModel {
    version: string,
    accuracy: u8,
    training_data_size: u256,
    last_updated: Timestamp,
    feature_weights: HashMap<string, u256>,
    threshold_scores: HashMap<RiskLevel, u8>
}

// Events
event FraudAnalysisCompleted(claim_id: u256, fraud_score: u8, risk_level: RiskLevel);
event HighRiskClaimDetected(claim_id: u256, patterns: Vec<FraudPattern>);
event ProviderFlagged(provider: address, reason: string, risk_score: u8);
event PatientFlagged(patient: address, reason: string, risk_score: u8);
event MLModelUpdated(version: string, accuracy: u8);
event ManualReviewRequired(claim_id: u256, reason: string);

contract FraudDetector {
    // State variables
    mapping(u256 => FraudAnalysis) public fraud_analyses;
    mapping(address => ProviderBehavior) public provider_behaviors;
    mapping(address => PatientBehavior) public patient_behaviors;
    mapping(string => u256) public procedure_frequency;
    mapping(string => u256) public diagnosis_frequency;
    
    // ML model storage
    MLModel public current_model;
    mapping(string => MLModel) public model_versions;
    
    // Statistical data for anomaly detection
    u256 public average_claim_amount;
    u256 public median_claim_amount;
    u256 public standard_deviation;
    u256 public total_claims_analyzed;
    
    // Fraud detection parameters
    u8 public high_risk_threshold; // Default: 75
    u8 public manual_review_threshold; // Default: 60
    u256 public large_claim_threshold; // Default: $50,000
    u256 public frequency_threshold; // Claims per month threshold
    
    // Access control
    address public admin;
    address public claims_processor;
    mapping(address => bool) public fraud_analysts;
    mapping(address => bool) public ml_engineers;
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyClaimsProcessor() {
        require(msg.sender == claims_processor, "Only claims processor can call this");
        _;
    }
    
    modifier onlyFraudAnalyst() {
        require(fraud_analysts[msg.sender] || msg.sender == admin, "Only fraud analysts can perform this action");
        _;
    }
    
    modifier onlyMLEngineer() {
        require(ml_engineers[msg.sender] || msg.sender == admin, "Only ML engineers can perform this action");
        _;
    }
    
    // Constructor
    constructor(address _claims_processor) {
        admin = msg.sender;
        claims_processor = _claims_processor;
        high_risk_threshold = 75;
        manual_review_threshold = 60;
        large_claim_threshold = 50000 * 10**18; // $50,000
        frequency_threshold = 10; // 10 claims per month
        
        // Initialize default ML model
        _initialize_default_model();
        
        // Set admin as initial analyst and engineer
        fraud_analysts[admin] = true;
        ml_engineers[admin] = true;
    }
    
    // Main fraud detection function
    function analyze_claim(
        u256 claim_id,
        address policy_holder,
        address provider,
        u256 amount,
        string procedure_code,
        string diagnosis_code,
        Timestamp treatment_date,
        Timestamp submission_date,
        bool is_emergency
    ) public onlyClaimsProcessor returns (FraudAnalysis memory) {
        
        // Update behavioral data
        _update_provider_behavior(provider, amount);
        _update_patient_behavior(policy_holder, amount, provider, procedure_code);
        
        // Perform comprehensive fraud analysis
        FraudAnalysis memory analysis = _perform_fraud_analysis(
            claim_id,
            policy_holder,
            provider,
            amount,
            procedure_code,
            diagnosis_code,
            treatment_date,
            submission_date,
            is_emergency
        );
        
        // Store analysis results
        fraud_analyses[claim_id] = analysis;
        total_claims_analyzed++;
        
        // Update statistical data
        _update_statistics(amount);
        
        // Emit events based on risk level
        emit FraudAnalysisCompleted(claim_id, analysis.overall_score, analysis.risk_level);
        
        if (analysis.risk_level == RiskLevel::High || analysis.risk_level == RiskLevel::Critical) {
            emit HighRiskClaimDetected(claim_id, analysis.detected_patterns);
        }
        
        if (analysis.requires_manual_review) {
            emit ManualReviewRequired(claim_id, "High fraud score detected");
        }
        
        return analysis;
    }
    
    // Comprehensive fraud analysis implementation
    function _perform_fraud_analysis(
        u256 claim_id,
        address policy_holder,
        address provider,
        u256 amount,
        string procedure_code,
        string diagnosis_code,
        Timestamp treatment_date,
        Timestamp submission_date,
        bool is_emergency
    ) internal view returns (FraudAnalysis memory) {
        
        Vec<FraudPattern> detected_patterns;
        u256 total_score = 0;
        u256 pattern_count = 0;
        
        // 1. Amount-based analysis
        (u8 amount_score, bool amount_anomaly) = _analyze_amount(amount, procedure_code);
        total_score += amount_score;
        if (amount_anomaly) {
            detected_patterns.push(FraudPattern::UnusualAmount);
            pattern_count++;
        }
        
        // 2. Frequency analysis
        (u8 frequency_score, bool frequency_anomaly) = _analyze_frequency(policy_holder, submission_date);
        total_score += frequency_score;
        if (frequency_anomaly) {
            detected_patterns.push(FraudPattern::FrequencyAnomaly);
            pattern_count++;
        }
        
        // 3. Provider behavior analysis
        (u8 provider_score, bool provider_suspicious) = _analyze_provider_behavior(provider, amount, procedure_code);
        total_score += provider_score;
        if (provider_suspicious) {
            detected_patterns.push(FraudPattern::ProviderCollusion);
            pattern_count++;
        }
        
        // 4. Timing analysis
        (u8 timing_score, bool timing_anomaly) = _analyze_timing(treatment_date, submission_date, is_emergency);
        total_score += timing_score;
        if (timing_anomaly) {
            detected_patterns.push(FraudPattern::TimingAnomaly);
            pattern_count++;
        }
        
        // 5. Geographic analysis
        (u8 geo_score, bool geo_anomaly) = _analyze_geographic_patterns(policy_holder, provider);
        total_score += geo_score;
        if (geo_anomaly) {
            detected_patterns.push(FraudPattern::GeographicAnomaly);
            pattern_count++;
        }
        
        // 6. Procedure stacking analysis
        (u8 stacking_score, bool stacking_detected) = _analyze_procedure_stacking(policy_holder, procedure_code, treatment_date);
        total_score += stacking_score;
        if (stacking_detected) {
            detected_patterns.push(FraudPattern::ProcedureStacking);
            pattern_count++;
        }
        
        // 7. ML model prediction
        u8 ml_score = _get_ml_prediction(policy_holder, provider, amount, procedure_code, diagnosis_code);
        total_score += ml_score;
        
        // Calculate final score (weighted average)
        u8 final_score = u8(total_score / 7); // 7 analysis components
        
        // Adjust score based on pattern count
        if (pattern_count >= 3) {
            final_score = final_score > 85 ? 100 : final_score + 15;
        } else if (pattern_count >= 2) {
            final_score = final_score > 90 ? 100 : final_score + 10;
        }
        
        // Determine risk level
        RiskLevel risk_level = _calculate_risk_level(final_score);
        
        // Determine if manual review is required
        bool requires_manual_review = final_score >= manual_review_threshold || 
                                    pattern_count >= 2 ||
                                    amount >= large_claim_threshold;
        
        return FraudAnalysis {
            claim_id: claim_id,
            overall_score: final_score,
            risk_level: risk_level,
            detected_patterns: detected_patterns,
            confidence: _calculate_confidence(pattern_count, final_score),
            analysis_timestamp: block.timestamp,
            analyst: address(this), // Automated analysis
            requires_manual_review: requires_manual_review,
            ml_model_version: current_model.version
        };
    }
    
    // Amount analysis
    function _analyze_amount(u256 amount, string procedure_code) internal view returns (u8, bool) {
        u8 score = 0;
        bool anomaly = false;
        
        // Check against statistical norms
        if (amount > average_claim_amount * 3) {
            score += 30;
            anomaly = true;
        } else if (amount > average_claim_amount * 2) {
            score += 20;
        }
        
        // Check against procedure-specific norms
        u256 procedure_avg = _get_procedure_average(procedure_code);
        if (procedure_avg > 0 && amount > procedure_avg * 2) {
            score += 25;
            anomaly = true;
        }
        
        // Check for round numbers (often suspicious)
        if (amount % (1000 * 10**18) == 0 && amount >= 5000 * 10**18) {
            score += 15;
        }
        
        return (score > 100 ? 100 : score, anomaly);
    }
    
    // Frequency analysis
    function _analyze_frequency(address patient, Timestamp submission_date) internal view returns (u8, bool) {
        PatientBehavior memory behavior = patient_behaviors[patient];
        u8 score = 0;
        bool anomaly = false;
        
        // Check claim frequency
        u256 time_since_last = submission_date - behavior.last_claim_date;
        u256 monthly_frequency = behavior.claim_frequency * 30 days / (submission_date - behavior.last_claim_date + 1);
        
        if (monthly_frequency > frequency_threshold) {
            score += 40;
            anomaly = true;
        } else if (monthly_frequency > frequency_threshold / 2) {
            score += 25;
        }
        
        // Check for rapid successive claims
        if (time_since_last < 24 hours) {
            score += 30;
            anomaly = true;
        } else if (time_since_last < 7 days) {
            score += 15;
        }
        
        return (score > 100 ? 100 : score, anomaly);
    }
    
    // Provider behavior analysis
    function _analyze_provider_behavior(address provider, u256 amount, string procedure_code) internal view returns (u8, bool) {
        ProviderBehavior memory behavior = provider_behaviors[provider];
        u8 score = 0;
        bool suspicious = false;
        
        // Check provider risk score
        score += behavior.risk_score / 2;
        
        // Check if amount is unusual for this provider
        if (behavior.average_claim_amount > 0 && amount > behavior.average_claim_amount * 3) {
            score += 25;
            suspicious = true;
        }
        
        // Check rejection rate
        if (behavior.rejection_rate > 30) {
            score += 20;
        }
        
        // Check fraud incidents
        if (behavior.fraud_incidents > 5) {
            score += 30;
            suspicious = true;
        }
        
        return (score > 100 ? 100 : score, suspicious);
    }
    
    // Timing analysis
    function _analyze_timing(Timestamp treatment_date, Timestamp submission_date, bool is_emergency) internal pure returns (u8, bool) {
        u8 score = 0;
        bool anomaly = false;
        
        u256 time_diff = submission_date - treatment_date;
        
        // Check submission delay
        if (!is_emergency && time_diff > 90 days) {
            score += 35;
            anomaly = true;
        } else if (!is_emergency && time_diff > 30 days) {
            score += 20;
        }
        
        // Check for immediate submission (sometimes suspicious)
        if (time_diff < 1 hours && !is_emergency) {
            score += 15;
        }
        
        // Check for weekend/holiday submissions
        if (_is_weekend_or_holiday(submission_date)) {
            score += 10;
        }
        
        return (score > 100 ? 100 : score, anomaly);
    }
    
    // Geographic analysis
    function _analyze_geographic_patterns(address patient, address provider) internal view returns (u8, bool) {
        PatientBehavior memory patient_behavior = patient_behaviors[patient];
        ProviderBehavior memory provider_behavior = provider_behaviors[provider];
        
        u8 score = 0;
        bool anomaly = false;
        
        // Check if patient is using providers in unusual geographic spread
        if (patient_behavior.geographic_spread > 5) {
            score += 25;
            anomaly = true;
        }
        
        // Additional geographic analysis would require location data
        // This is a simplified implementation
        
        return (score > 100 ? 100 : score, anomaly);
    }
    
    // Procedure stacking analysis
    function _analyze_procedure_stacking(address patient, string procedure_code, Timestamp treatment_date) internal view returns (u8, bool) {
        u8 score = 0;
        bool stacking_detected = false;
        
        // This would analyze if multiple procedures are being billed together suspiciously
        // Simplified implementation
        
        return (score, stacking_detected);
    }
    
    // ML model prediction
    function _get_ml_prediction(address patient, address provider, u256 amount, string procedure_code, string diagnosis_code) internal view returns (u8) {
        // This would integrate with the actual ML model
        // For now, return a simplified score based on available data
        
        u8 base_score = 20;
        
        // Add weights based on current model
        PatientBehavior memory patient_behavior = patient_behaviors[patient];
        ProviderBehavior memory provider_behavior = provider_behaviors[provider];
        
        base_score += patient_behavior.risk_score / 4;
        base_score += provider_behavior.risk_score / 4;
        
        return base_score > 100 ? 100 : base_score;
    }
    
    // Risk level calculation
    function _calculate_risk_level(u8 score) internal pure returns (RiskLevel) {
        if (score >= 76) return RiskLevel::Critical;
        if (score >= 51) return RiskLevel::High;
        if (score >= 26) return RiskLevel::Medium;
        return RiskLevel::Low;
    }
    
    // Confidence calculation
    function _calculate_confidence(u256 pattern_count, u8 score) internal pure returns (u8) {
        u8 confidence = 50; // Base confidence
        
        // Increase confidence with more patterns detected
        confidence += u8(pattern_count * 10);
        
        // Increase confidence with higher scores
        if (score >= 80) confidence += 20;
        else if (score >= 60) confidence += 10;
        
        return confidence > 100 ? 100 : confidence;
    }
    
    // Update provider behavior
    function _update_provider_behavior(address provider, u256 amount) internal {
        ProviderBehavior storage behavior = provider_behaviors[provider];
        
        behavior.total_claims++;
        behavior.total_amount += amount;
        behavior.average_claim_amount = behavior.total_amount / behavior.total_claims;
    }
    
    // Update patient behavior
    function _update_patient_behavior(address patient, u256 amount, address provider, string procedure_code) internal {
        PatientBehavior storage behavior = patient_behaviors[patient];
        
        behavior.claim_frequency++;
        behavior.last_claim_date = block.timestamp;
        
        // Update average claim amount
        behavior.average_claim_amount = (behavior.average_claim_amount * (behavior.claim_frequency - 1) + amount) / behavior.claim_frequency;
    }
    
    // Update statistical data
    function _update_statistics(u256 amount) internal {
        // Update running average
        average_claim_amount = (average_claim_amount * total_claims_analyzed + amount) / (total_claims_analyzed + 1);
        
        // Update procedure frequency
        // This would be more complex in a real implementation
    }
    
    // Initialize default ML model
    function _initialize_default_model() internal {
        current_model = MLModel {
            version: "v1.0.0",
            accuracy: 85,
            training_data_size: 10000,
            last_updated: block.timestamp,
            feature_weights: HashMap<string, u256>(),
            threshold_scores: HashMap<RiskLevel, u8>()
        };
        
        // Set default thresholds
        current_model.threshold_scores[RiskLevel::Low] = 25;
        current_model.threshold_scores[RiskLevel::Medium] = 50;
        current_model.threshold_scores[RiskLevel::High] = 75;
        current_model.threshold_scores[RiskLevel::Critical] = 90;
    }
    
    // Utility functions
    function _get_procedure_average(string procedure_code) internal view returns (u256) {
        // This would return the average amount for a specific procedure
        // Simplified implementation
        return average_claim_amount;
    }
    
    function _is_weekend_or_holiday(Timestamp timestamp) internal pure returns (bool) {
        u256 day_of_week = (timestamp / 86400 + 4) % 7;
        return day_of_week == 5 || day_of_week == 6; // Saturday or Sunday
    }
    
    // Administrative functions
    function update_ml_model(
        string version,
        u8 accuracy,
        u256 training_data_size,
        HashMap<string, u256> feature_weights
    ) public onlyMLEngineer {
        model_versions[current_model.version] = current_model; // Archive current model
        
        current_model = MLModel {
            version: version,
            accuracy: accuracy,
            training_data_size: training_data_size,
            last_updated: block.timestamp,
            feature_weights: feature_weights,
            threshold_scores: current_model.threshold_scores // Keep existing thresholds
        };
        
        emit MLModelUpdated(version, accuracy);
    }
    
    function set_thresholds(u8 high_risk, u8 manual_review) public onlyAdmin {
        require(high_risk <= 100 && manual_review <= 100, "Thresholds must be <= 100");
        high_risk_threshold = high_risk;
        manual_review_threshold = manual_review;
    }
    
    function flag_provider(address provider, string reason) public onlyFraudAnalyst {
        ProviderBehavior storage behavior = provider_behaviors[provider];
        behavior.risk_score = behavior.risk_score < 80 ? behavior.risk_score + 20 : 100;
        emit ProviderFlagged(provider, reason, behavior.risk_score);
    }
    
    function flag_patient(address patient, string reason) public onlyFraudAnalyst {
        PatientBehavior storage behavior = patient_behaviors[patient];
        behavior.risk_score = behavior.risk_score < 80 ? behavior.risk_score + 20 : 100;
        emit PatientFlagged(patient, reason, behavior.risk_score);
    }
    
    // Access control functions
    function add_fraud_analyst(address analyst) public onlyAdmin {
        fraud_analysts[analyst] = true;
    }
    
    function add_ml_engineer(address engineer) public onlyAdmin {
        ml_engineers[engineer] = true;
    }
    
    // View functions
    function get_fraud_analysis(u256 claim_id) public view returns (FraudAnalysis memory) {
        return fraud_analyses[claim_id];
    }
    
    function get_provider_behavior(address provider) public view returns (ProviderBehavior memory) {
        return provider_behaviors[provider];
    }
    
    function get_patient_behavior(address patient) public view returns (PatientBehavior memory) {
        return patient_behaviors[patient];
    }
    
    function get_current_model() public view returns (MLModel memory) {
        return current_model;
    }
    
    function get_statistics() public view returns (u256, u256, u256, u256) {
        return (average_claim_amount, median_claim_amount, standard_deviation, total_claims_analyzed);
    }
}