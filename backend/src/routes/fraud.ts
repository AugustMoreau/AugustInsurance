import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import redisService from '../services/RedisService';
import blockchainService from '../services/BlockchainService';
import { validate, commonSchemas } from '../middleware/validation';
import { authMiddleware, requirePermission, requireRole, PERMISSIONS } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import {
  AppError,
  ValidationError,
  NotFoundError,
  BusinessLogicError,
  BlockchainError,
} from '../middleware/errorHandler';

const router = Router();

// Apply authentication to all routes
router.use(authMiddleware);

// Helper function to calculate fraud risk score
const calculateFraudRiskScore = async (claimData: any): Promise<number> => {
  const {
    amount,
    providerId,
    patientId,
    procedureCode,
    diagnosisCode,
    serviceDate,
    submissionTime,
  } = claimData;

  let riskScore = 0;

  // Amount-based risk factors
  if (amount > 50000) {
    riskScore += 25;
  } else if (amount > 20000) {
    riskScore += 15;
  } else if (amount > 10000) {
    riskScore += 10;
  }

  // Provider history analysis
  const providerStatsResult = await databaseService.query(
    `SELECT 
       COUNT(*) as total_claims,
       COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_claims,
       AVG(amount) as avg_amount,
       COUNT(CASE WHEN fa.risk_level = 'high' THEN 1 END) as high_risk_claims
     FROM claims c
     LEFT JOIN fraud_analysis fa ON c.id = fa.claim_id
     WHERE c.provider_id = $1 AND c.submitted_at >= NOW() - INTERVAL '6 months'`,
    [providerId],
  );

  const providerStats = providerStatsResult.rows[0];
  const totalClaims = parseInt(providerStats.total_claims);

  if (totalClaims > 0) {
    const rejectionRate = parseInt(providerStats.rejected_claims) / totalClaims;
    const highRiskRate = parseInt(providerStats.high_risk_claims) / totalClaims;
    const avgAmount = parseFloat(providerStats.avg_amount || 0);

    if (rejectionRate > 0.3) {
      riskScore += 20;
    } else if (rejectionRate > 0.15) {
      riskScore += 10;
    }

    if (highRiskRate > 0.2) {
      riskScore += 15;
    } else if (highRiskRate > 0.1) {
      riskScore += 8;
    }

    // Unusual amount compared to provider's average
    if (avgAmount > 0 && amount > avgAmount * 3) {
      riskScore += 15;
    }
  }

  // Patient history analysis
  const patientStatsResult = await databaseService.query(
    `SELECT 
       COUNT(*) as total_claims,
       COUNT(CASE WHEN submitted_at >= NOW() - INTERVAL '30 days' THEN 1 END) as recent_claims,
       COUNT(DISTINCT provider_id) as unique_providers
     FROM claims 
     WHERE patient_id = $1 AND submitted_at >= NOW() - INTERVAL '6 months'`,
    [patientId],
  );

  const patientStats = patientStatsResult.rows[0];
  const recentClaims = parseInt(patientStats.recent_claims);
  const uniqueProviders = parseInt(patientStats.unique_providers);

  // High frequency of recent claims
  if (recentClaims > 10) {
    riskScore += 20;
  } else if (recentClaims > 5) {
    riskScore += 10;
  }

  // Multiple providers (potential doctor shopping)
  if (uniqueProviders > 5) {
    riskScore += 15;
  } else if (uniqueProviders > 3) {
    riskScore += 8;
  }

  // Timing analysis
  const serviceDateTime = new Date(serviceDate);
  const submissionDateTime = new Date(submissionTime);
  const timeDiff = submissionDateTime.getTime() - serviceDateTime.getTime();
  const daysDiff = timeDiff / (1000 * 60 * 60 * 24);

  // Very quick submission (same day) or very delayed submission
  if (daysDiff < 1) {
    riskScore += 10;
  } else if (daysDiff > 90) {
    riskScore += 15;
  }

  // Weekend or holiday service dates (higher risk)
  const dayOfWeek = serviceDateTime.getDay();
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    riskScore += 5;
  }

  // Procedure and diagnosis code analysis
  const procedureDiagnosisResult = await databaseService.query(
    `SELECT COUNT(*) as count
     FROM claims 
     WHERE procedure_code = $1 AND diagnosis_code = $2 
     AND submitted_at >= NOW() - INTERVAL '30 days'
     AND provider_id = $3`,
    [procedureCode, diagnosisCode, providerId],
  );

  const procedureDiagnosisCount = parseInt(procedureDiagnosisResult.rows[0].count);

  // Repetitive procedure-diagnosis combinations
  if (procedureDiagnosisCount > 20) {
    riskScore += 15;
  } else if (procedureDiagnosisCount > 10) {
    riskScore += 8;
  }

  return Math.min(riskScore, 100);
};

// Helper function to detect fraud patterns
const detectFraudPatterns = async (claimData: any): Promise<string[]> => {
  const patterns = [];
  const { amount, providerId, patientId, procedureCode, diagnosisCode, serviceDate } = claimData;

  // Pattern 1: Billing for services not rendered (unusual timing)
  const serviceDateTime = new Date(serviceDate);
  const now = new Date();
  if (serviceDateTime > now) {
    patterns.push('future_service_date');
  }

  // Pattern 2: Upcoding (billing for more expensive procedures)
  const similarProceduresResult = await databaseService.query(
    `SELECT procedure_code, AVG(amount) as avg_amount
     FROM claims 
     WHERE procedure_code LIKE $1 AND provider_id = $2
     AND submitted_at >= NOW() - INTERVAL '6 months'
     GROUP BY procedure_code
     ORDER BY avg_amount DESC`,
    [`${procedureCode.substring(0, 3)}%`, providerId],
  );

  if (similarProceduresResult.rows.length > 1) {
    const currentProcedureAvg = similarProceduresResult.rows.find(row => row.procedure_code === procedureCode)?.avg_amount || 0;
    const highestAvg = parseFloat(similarProceduresResult.rows[0].avg_amount);

    if (amount > highestAvg * 1.5) {
      patterns.push('potential_upcoding');
    }
  }

  // Pattern 3: Unbundling (billing separately for services that should be bundled)
  const sameDayClaimsResult = await databaseService.query(
    `SELECT COUNT(*) as count, array_agg(procedure_code) as procedures
     FROM claims 
     WHERE provider_id = $1 AND patient_id = $2 AND service_date = $3
     AND id != $4`,
    [providerId, patientId, serviceDate, claimData.id || 'new'],
  );

  const sameDayClaims = parseInt(sameDayClaimsResult.rows[0].count);
  if (sameDayClaims > 3) {
    patterns.push('potential_unbundling');
  }

  // Pattern 4: Phantom billing (billing for non-existent patients)
  const patientVerificationResult = await databaseService.query(
    'SELECT id, created_at FROM users WHERE id = $1 AND role = $2',
    [patientId, 'patient'],
  );

  if (patientVerificationResult.rows.length === 0) {
    patterns.push('invalid_patient');
  } else {
    const patientCreated = new Date(patientVerificationResult.rows[0].created_at);
    const claimService = new Date(serviceDate);

    if (claimService < patientCreated) {
      patterns.push('service_before_registration');
    }
  }

  // Pattern 5: Duplicate billing
  const duplicateResult = await databaseService.query(
    `SELECT COUNT(*) as count
     FROM claims 
     WHERE provider_id = $1 AND patient_id = $2 AND procedure_code = $3 
     AND diagnosis_code = $4 AND service_date = $5 AND amount = $6
     AND id != $7`,
    [providerId, patientId, procedureCode, diagnosisCode, serviceDate, amount, claimData.id || 'new'],
  );

  const duplicateCount = parseInt(duplicateResult.rows[0].count);
  if (duplicateCount > 0) {
    patterns.push('duplicate_billing');
  }

  // Pattern 6: Excessive billing frequency
  const frequencyResult = await databaseService.query(
    `SELECT COUNT(*) as count
     FROM claims 
     WHERE provider_id = $1 AND procedure_code = $2
     AND submitted_at >= NOW() - INTERVAL '7 days'`,
    [providerId, procedureCode],
  );

  const weeklyFrequency = parseInt(frequencyResult.rows[0].count);
  if (weeklyFrequency > 50) {
    patterns.push('excessive_billing_frequency');
  }

  return patterns;
};

/**
 * @swagger
 * /api/fraud/analyze:
 *   post:
 *     summary: Analyze a claim for fraud indicators
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - claimId
 *             properties:
 *               claimId:
 *                 type: string
 *                 format: uuid
 *               forceReanalysis:
 *                 type: boolean
 *                 default: false
 *     responses:
 *       200:
 *         description: Fraud analysis completed
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Claim not found
 */
router.post('/analyze',
  requireRole(['admin', 'fraud_analyst', 'claims_processor']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { claimId, forceReanalysis = false } = req.body;
    const userId = req.user!.id;

    if (!claimId) {
      throw new ValidationError('claimId is required');
    }

    // Check if analysis already exists
    if (!forceReanalysis) {
      const existingAnalysis = await databaseService.query(
        'SELECT * FROM fraud_analysis WHERE claim_id = $1 ORDER BY created_at DESC LIMIT 1',
        [claimId],
      );

      if (existingAnalysis.rows.length > 0) {
        const analysis = existingAnalysis.rows[0];
        return res.json({
          message: 'Existing fraud analysis found',
          analysis: {
            id: analysis.id,
            claimId: analysis.claim_id,
            riskScore: analysis.risk_score,
            riskLevel: analysis.risk_level,
            fraudPatterns: analysis.fraud_patterns,
            mlPrediction: analysis.ml_prediction,
            confidence: analysis.confidence,
            flaggedReasons: analysis.flagged_reasons,
            createdAt: analysis.created_at,
          },
        });
      }
    }

    // Get claim details
    const claimResult = await databaseService.query(
      `SELECT c.*, p.risk_score as provider_risk_score
       FROM claims c
       LEFT JOIN providers p ON c.provider_id = p.id
       WHERE c.id = $1`,
      [claimId],
    );

    if (claimResult.rows.length === 0) {
      throw new NotFoundError('Claim');
    }

    const claim = claimResult.rows[0];

    const analysisId = uuidv4();

    await databaseService.query('BEGIN');

    try {
      // Calculate fraud risk score
      const riskScore = await calculateFraudRiskScore({
        amount: claim.amount,
        providerId: claim.provider_id,
        patientId: claim.patient_id,
        procedureCode: claim.procedure_code,
        diagnosisCode: claim.diagnosis_code,
        serviceDate: claim.service_date,
        submissionTime: claim.submitted_at,
        id: claim.id,
      });

      // Detect fraud patterns
      const fraudPatterns = await detectFraudPatterns({
        amount: claim.amount,
        providerId: claim.provider_id,
        patientId: claim.patient_id,
        procedureCode: claim.procedure_code,
        diagnosisCode: claim.diagnosis_code,
        serviceDate: claim.service_date,
        id: claim.id,
      });

      // Determine risk level
      let riskLevel = 'low';
      if (riskScore >= 70) {
        riskLevel = 'high';
      } else if (riskScore >= 40) {
        riskLevel = 'medium';
      }

      // Use blockchain for ML prediction
      let mlPrediction = null;
      let confidence = null;

      try {
        const blockchainAnalysis = await blockchainService.analyzeClaim(
          claimId,
          claim.amount.toString(),
          claim.provider_id,
          claim.patient_id,
          JSON.stringify(fraudPatterns),
          {}, // options parameter
        );

        mlPrediction = (blockchainAnalysis as any).prediction || 'medium';
        confidence = (blockchainAnalysis as any).confidence || 0.5;
      } catch (blockchainError) {
        logger.warn('Blockchain ML analysis failed, using local analysis', {
          claimId,
          error: (blockchainError as Error).message,
        });

        // Fallback to simple rule-based prediction
        mlPrediction = riskScore > 60 ? 'fraudulent' : 'legitimate';
        confidence = Math.max(0.5, (100 - Math.abs(riskScore - 50)) / 100);
      }

      // Generate flagged reasons
      const flaggedReasons = [];

      if (riskScore > 70) {
        flaggedReasons.push('High risk score');
      }
      if (fraudPatterns.length > 0) {
        flaggedReasons.push(`Fraud patterns detected: ${fraudPatterns.join(', ')}`);
      }
      if (claim.amount > 25000) {
        flaggedReasons.push('High claim amount');
      }
      if (claim.provider_risk_score > 60) {
        flaggedReasons.push('High-risk provider');
      }
      if (mlPrediction === 'fraudulent' && confidence > 0.7) {
        flaggedReasons.push('ML model flagged as fraudulent');
      }

      // Save fraud analysis
      const analysisResult = await databaseService.query(
        `INSERT INTO fraud_analysis (
          id, claim_id, risk_score, risk_level, fraud_patterns, ml_prediction,
          confidence, flagged_reasons, analyzed_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
        [
          analysisId,
          claimId,
          riskScore,
          riskLevel,
          JSON.stringify(fraudPatterns),
          mlPrediction,
          confidence,
          JSON.stringify(flaggedReasons),
          userId,
        ],
      );

      const analysis = analysisResult.rows[0];

      // Update claim with fraud analysis results
      await databaseService.query(
        'UPDATE claims SET fraud_score = $1, fraud_indicators = $2 WHERE id = $3',
        [riskScore, JSON.stringify(fraudPatterns), claimId],
      );

      await databaseService.query('COMMIT');

      // Cache analysis results
      await redisService.set(`fraud_analysis:${claimId}`, analysis, { ttl: 3600 });

      logger.info('Fraud analysis completed', {
        analysisId,
        claimId,
        riskScore,
        riskLevel,
        fraudPatterns,
        mlPrediction,
        confidence,
        analyzedBy: userId,
      });

      res.json({
        message: 'Fraud analysis completed successfully',
        analysis: {
          id: analysis.id,
          claimId: analysis.claim_id,
          riskScore: analysis.risk_score,
          riskLevel: analysis.risk_level,
          fraudPatterns: analysis.fraud_patterns,
          mlPrediction: analysis.ml_prediction,
          confidence: analysis.confidence,
          flaggedReasons: analysis.flagged_reasons,
          createdAt: analysis.created_at,
        },
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/fraud/analysis:
 *   get:
 *     summary: Get fraud analysis results with filtering
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *       - in: query
 *         name: riskLevel
 *         schema:
 *           type: string
 *           enum: [low, medium, high]
 *       - in: query
 *         name: mlPrediction
 *         schema:
 *           type: string
 *           enum: [legitimate, fraudulent]
 *       - in: query
 *         name: minRiskScore
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *       - in: query
 *         name: dateFrom
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: dateTo
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Fraud analysis results retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/analysis',
  requireRole(['admin', 'fraud_analyst', 'claims_processor']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      riskLevel,
      mlPrediction,
      minRiskScore,
      dateFrom,
      dateTo,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);

    // Build WHERE clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (riskLevel) {
      conditions.push(`fa.risk_level = $${paramIndex++}`);
      params.push(riskLevel);
    }

    if (mlPrediction) {
      conditions.push(`fa.ml_prediction = $${paramIndex++}`);
      params.push(mlPrediction);
    }

    if (minRiskScore) {
      conditions.push(`fa.risk_score >= $${paramIndex++}`);
      params.push(Number(minRiskScore));
    }

    if (dateFrom) {
      conditions.push(`fa.created_at >= $${paramIndex++}`);
      params.push(dateFrom);
    }

    if (dateTo) {
      conditions.push(`fa.created_at <= $${paramIndex++}`);
      params.push(`${dateTo} 23:59:59`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM fraud_analysis fa
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get fraud analysis results
    const analysisQuery = `
      SELECT 
        fa.id, fa.claim_id, fa.risk_score, fa.risk_level, fa.fraud_patterns,
        fa.ml_prediction, fa.confidence, fa.flagged_reasons, fa.created_at,
        c.amount, c.procedure_code, c.diagnosis_code, c.service_date, c.status as claim_status,
        p.name as provider_name, p.npi as provider_npi,
        u.first_name as patient_first_name, u.last_name as patient_last_name
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      LEFT JOIN providers p ON c.provider_id = p.id
      LEFT JOIN users u ON c.patient_id = u.id
      ${whereClause}
      ORDER BY fa.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const analysisResult = await databaseService.query(analysisQuery, params);

    const analyses = analysisResult.rows.map(row => ({
      id: row.id,
      claimId: row.claim_id,
      claimInfo: {
        amount: parseFloat(row.amount),
        procedureCode: row.procedure_code,
        diagnosisCode: row.diagnosis_code,
        serviceDate: row.service_date,
        status: row.claim_status,
      },
      providerInfo: {
        name: row.provider_name,
        npi: row.provider_npi,
      },
      patientInfo: {
        name: `${row.patient_first_name} ${row.patient_last_name}`,
      },
      riskScore: row.risk_score,
      riskLevel: row.risk_level,
      fraudPatterns: row.fraud_patterns,
      mlPrediction: row.ml_prediction,
      confidence: row.confidence,
      flaggedReasons: row.flagged_reasons,
      createdAt: row.created_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      analyses,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        totalPages,
        hasNext: Number(page) < totalPages,
        hasPrev: Number(page) > 1,
      },
    });
  }),
);

/**
 * @swagger
 * /api/fraud/analysis/{id}:
 *   get:
 *     summary: Get detailed fraud analysis by ID
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Fraud analysis retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Analysis not found
 */
router.get('/analysis/:id',
  requireRole(['admin', 'fraud_analyst', 'claims_processor']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;

    // Check cache first
    const cachedAnalysis = await redisService.get(`fraud_analysis_detail:${id}`);
    if (cachedAnalysis) {
      return res.json({ analysis: cachedAnalysis });
    }

    const analysisQuery = `
      SELECT 
        fa.*,
        c.amount, c.procedure_code, c.diagnosis_code, c.service_date, c.status as claim_status,
        c.submitted_at, c.urgency, c.priority,
        p.name as provider_name, p.npi as provider_npi, p.risk_score as provider_risk_score,
        p.specialties as provider_specialties,
        u.first_name as patient_first_name, u.last_name as patient_last_name,
        u.date_of_birth as patient_dob,
        pol.policy_number, pol.coverage_type
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      LEFT JOIN providers p ON c.provider_id = p.id
      LEFT JOIN users u ON c.patient_id = u.id
      LEFT JOIN policies pol ON c.policy_id = pol.id
      WHERE fa.id = $1
    `;

    const result = await databaseService.query(analysisQuery, [id]);

    if (result.rows.length === 0) {
      throw new NotFoundError('Fraud analysis');
    }

    const row = result.rows[0];

    // Get related fraud analyses for the same provider
    const relatedAnalysesResult = await databaseService.query(
      `SELECT fa.id, fa.risk_score, fa.risk_level, fa.created_at, c.amount
       FROM fraud_analysis fa
       LEFT JOIN claims c ON fa.claim_id = c.id
       WHERE c.provider_id = (SELECT provider_id FROM claims WHERE id = $1)
       AND fa.id != $2
       ORDER BY fa.created_at DESC
       LIMIT 10`,
      [row.claim_id, id],
    );

    const relatedAnalyses = relatedAnalysesResult.rows.map(related => ({
      id: related.id,
      riskScore: related.risk_score,
      riskLevel: related.risk_level,
      amount: parseFloat(related.amount),
      createdAt: related.created_at,
    }));

    const analysis = {
      id: row.id,
      claimId: row.claim_id,
      claimInfo: {
        amount: parseFloat(row.amount),
        procedureCode: row.procedure_code,
        diagnosisCode: row.diagnosis_code,
        serviceDate: row.service_date,
        submittedAt: row.submitted_at,
        status: row.claim_status,
        urgency: row.urgency,
        priority: row.priority,
        policyNumber: row.policy_number,
        coverageType: row.coverage_type,
      },
      providerInfo: {
        name: row.provider_name,
        npi: row.provider_npi,
        riskScore: row.provider_risk_score,
        specialties: row.provider_specialties,
      },
      patientInfo: {
        name: `${row.patient_first_name} ${row.patient_last_name}`,
        dateOfBirth: row.patient_dob,
      },
      riskScore: row.risk_score,
      riskLevel: row.risk_level,
      fraudPatterns: row.fraud_patterns,
      mlPrediction: row.ml_prediction,
      confidence: row.confidence,
      flaggedReasons: row.flagged_reasons,
      relatedAnalyses,
      createdAt: row.created_at,
      analyzedBy: row.analyzed_by,
    };

    // Cache the detailed analysis
    await redisService.set(`fraud_analysis_detail:${id}`, analysis, { ttl: 1800 });

    res.json({ analysis });
  }),
);

/**
 * @swagger
 * /api/fraud/patterns:
 *   get:
 *     summary: Get fraud pattern statistics
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [week, month, quarter, year]
 *           default: month
 *       - in: query
 *         name: providerId
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Fraud pattern statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/patterns',
  requireRole(['admin', 'fraud_analyst']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { period = 'month', providerId } = req.query;

    // Calculate date range
    const now = new Date();
    const startDate = new Date();

    switch (period) {
      case 'week':
        startDate.setDate(now.getDate() - 7);
        break;
      case 'month':
        startDate.setMonth(now.getMonth() - 1);
        break;
      case 'quarter':
        startDate.setMonth(now.getMonth() - 3);
        break;
      case 'year':
        startDate.setFullYear(now.getFullYear() - 1);
        break;
      default:
        startDate.setMonth(now.getMonth() - 1);
    }

    // Build WHERE clause
    const conditions = ['fa.created_at >= $1'];
    const params: any[] = [startDate];
    let paramIndex = 2;

    if (providerId) {
      conditions.push(`c.provider_id = $${paramIndex++}`);
      params.push(providerId as string);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Get pattern frequency
    const patternsQuery = `
      SELECT 
        jsonb_array_elements_text(fraud_patterns) as pattern,
        COUNT(*) as frequency,
        AVG(risk_score) as avg_risk_score
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      ${whereClause}
      GROUP BY pattern
      ORDER BY frequency DESC
    `;

    const patternsResult = await databaseService.query(patternsQuery, params);

    const patterns = patternsResult.rows.map(row => ({
      pattern: row.pattern,
      frequency: parseInt(row.frequency),
      averageRiskScore: parseFloat(row.avg_risk_score),
    }));

    // Get risk level distribution
    const riskLevelQuery = `
      SELECT 
        risk_level,
        COUNT(*) as count,
        AVG(risk_score) as avg_score
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      ${whereClause}
      GROUP BY risk_level
    `;

    const riskLevelResult = await databaseService.query(riskLevelQuery, params);

    const riskLevelDistribution = riskLevelResult.rows.reduce((acc, row) => {
      acc[row.risk_level] = {
        count: parseInt(row.count),
        averageScore: parseFloat(row.avg_score),
      };
      return acc;
    }, {});

    // Get ML prediction accuracy
    const mlAccuracyQuery = `
      SELECT 
        ml_prediction,
        COUNT(*) as count,
        AVG(confidence) as avg_confidence
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      ${whereClause}
      GROUP BY ml_prediction
    `;

    const mlAccuracyResult = await databaseService.query(mlAccuracyQuery, params);

    const mlPredictionStats = mlAccuracyResult.rows.reduce((acc, row) => {
      acc[row.ml_prediction] = {
        count: parseInt(row.count),
        averageConfidence: parseFloat(row.avg_confidence),
      };
      return acc;
    }, {});

    res.json({
      period,
      dateRange: {
        from: startDate,
        to: now,
      },
      patterns,
      riskLevelDistribution,
      mlPredictionStats,
    });
  }),
);

/**
 * @swagger
 * /api/fraud/providers/risk:
 *   get:
 *     summary: Get high-risk providers
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: minRiskScore
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *           default: 60
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *     responses:
 *       200:
 *         description: High-risk providers retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/providers/risk',
  requireRole(['admin', 'fraud_analyst']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { minRiskScore = 60, limit = 20 } = req.query;

    const providersQuery = `
      SELECT 
        p.id, p.name, p.npi, p.risk_score, p.specialties,
        COUNT(fa.id) as fraud_analyses_count,
        COUNT(CASE WHEN fa.risk_level = 'high' THEN 1 END) as high_risk_analyses,
        AVG(fa.risk_score) as avg_fraud_score,
        COUNT(c.id) as total_claims,
        COUNT(CASE WHEN c.status = 'rejected' THEN 1 END) as rejected_claims
      FROM providers p
      LEFT JOIN claims c ON p.id = c.provider_id
      LEFT JOIN fraud_analysis fa ON c.id = fa.claim_id
      WHERE p.risk_score >= $1 AND p.is_active = true
      GROUP BY p.id, p.name, p.npi, p.risk_score, p.specialties
      ORDER BY p.risk_score DESC, avg_fraud_score DESC
      LIMIT $2
    `;

    const result = await databaseService.query(providersQuery, [Number(minRiskScore), Number(limit)]);

    const providers = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      npi: row.npi,
      riskScore: row.risk_score,
      specialties: row.specialties,
      fraudAnalysesCount: parseInt(row.fraud_analyses_count),
      highRiskAnalyses: parseInt(row.high_risk_analyses),
      averageFraudScore: parseFloat(row.avg_fraud_score || 0),
      totalClaims: parseInt(row.total_claims),
      rejectedClaims: parseInt(row.rejected_claims),
      rejectionRate: row.total_claims > 0 ?
        ((row.rejected_claims / row.total_claims) * 100).toFixed(2) : 0,
    }));

    res.json({
      providers,
      criteria: {
        minRiskScore: Number(minRiskScore),
        limit: Number(limit),
      },
    });
  }),
);

/**
 * @swagger
 * /api/fraud/statistics:
 *   get:
 *     summary: Get fraud detection statistics
 *     tags: [Fraud Detection]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [week, month, quarter, year]
 *           default: month
 *     responses:
 *       200:
 *         description: Fraud statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/statistics',
  requireRole(['admin', 'fraud_analyst']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { period = 'month' } = req.query;

    // Calculate date range
    const now = new Date();
    const startDate = new Date();

    switch (period) {
      case 'week':
        startDate.setDate(now.getDate() - 7);
        break;
      case 'month':
        startDate.setMonth(now.getMonth() - 1);
        break;
      case 'quarter':
        startDate.setMonth(now.getMonth() - 3);
        break;
      case 'year':
        startDate.setFullYear(now.getFullYear() - 1);
        break;
      default:
        startDate.setMonth(now.getMonth() - 1);
    }

    // Get overall fraud statistics
    const statsQuery = `
      SELECT 
        COUNT(fa.id) as total_analyses,
        COUNT(CASE WHEN fa.risk_level = 'high' THEN 1 END) as high_risk_count,
        COUNT(CASE WHEN fa.ml_prediction = 'fraudulent' THEN 1 END) as predicted_fraudulent,
        AVG(fa.risk_score) as avg_risk_score,
        SUM(c.amount) as total_analyzed_amount,
        SUM(CASE WHEN fa.risk_level = 'high' THEN c.amount ELSE 0 END) as high_risk_amount
      FROM fraud_analysis fa
      LEFT JOIN claims c ON fa.claim_id = c.id
      WHERE fa.created_at >= $1
    `;

    const statsResult = await databaseService.query(statsQuery, [startDate]);
    const stats = statsResult.rows[0];

    // Get trend data (daily breakdown)
    const trendQuery = `
      SELECT 
        DATE(fa.created_at) as date,
        COUNT(fa.id) as analyses_count,
        COUNT(CASE WHEN fa.risk_level = 'high' THEN 1 END) as high_risk_count,
        AVG(fa.risk_score) as avg_risk_score
      FROM fraud_analysis fa
      WHERE fa.created_at >= $1
      GROUP BY DATE(fa.created_at)
      ORDER BY date
    `;

    const trendResult = await databaseService.query(trendQuery, [startDate]);

    const trends = trendResult.rows.map(row => ({
      date: row.date,
      analysesCount: parseInt(row.analyses_count),
      highRiskCount: parseInt(row.high_risk_count),
      averageRiskScore: parseFloat(row.avg_risk_score),
    }));

    res.json({
      period,
      dateRange: {
        from: startDate,
        to: now,
      },
      statistics: {
        totalAnalyses: parseInt(stats.total_analyses),
        highRiskCount: parseInt(stats.high_risk_count),
        predictedFraudulent: parseInt(stats.predicted_fraudulent),
        averageRiskScore: parseFloat(stats.avg_risk_score || 0),
        totalAnalyzedAmount: parseFloat(stats.total_analyzed_amount || 0),
        highRiskAmount: parseFloat(stats.high_risk_amount || 0),
        fraudDetectionRate: stats.total_analyses > 0 ?
          ((stats.high_risk_count / stats.total_analyses) * 100).toFixed(2) : 0,
      },
      trends,
    });
  }),
);

export default router;