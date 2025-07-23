import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import blockchainService from '../services/BlockchainService';
import redisService from '../services/RedisService';
import { validate, claimSchemas } from '../middleware/validation';
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

// Helper function to calculate claim priority
const calculateClaimPriority = (amount: number, urgency: string, diagnosisCode: string): string => {
  let priority = 'medium';

  // High-value claims
  if (amount > 50000) {
    priority = 'high';
  }

  // Emergency procedures
  if (urgency === 'emergency') {
    priority = 'high';
  }

  // Critical diagnosis codes (simplified)
  const criticalCodes = ['I21', 'I46', 'R57', 'J44', 'N17']; // Heart attack, cardiac arrest, shock, COPD, kidney failure
  if (criticalCodes.some(code => diagnosisCode.startsWith(code))) {
    priority = 'high';
  }

  return priority;
};

// Helper function to determine procedure category
const getProcedureCategory = (procedureCode: string): string => {
  const code = parseInt(procedureCode);

  if (code >= 10000 && code <= 19999) {
    return 'surgery';
  }
  if (code >= 20000 && code <= 29999) {
    return 'radiology';
  }
  if (code >= 30000 && code <= 39999) {
    return 'laboratory';
  }
  if (code >= 40000 && code <= 49999) {
    return 'medicine';
  }
  if (code >= 70000 && code <= 79999) {
    return 'radiology';
  }
  if (code >= 80000 && code <= 89999) {
    return 'pathology';
  }
  if (code >= 90000 && code <= 99999) {
    return 'medicine';
  }

  return 'other';
};

/**
 * @swagger
 * /api/claims:
 *   post:
 *     summary: Submit a new insurance claim
 *     tags: [Claims]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - policyId
 *               - providerId
 *               - patientId
 *               - serviceDate
 *               - diagnosisCode
 *               - procedureCode
 *               - amount
 *               - description
 *             properties:
 *               policyId:
 *                 type: string
 *                 format: uuid
 *               providerId:
 *                 type: string
 *                 format: uuid
 *               patientId:
 *                 type: string
 *                 format: uuid
 *               serviceDate:
 *                 type: string
 *                 format: date
 *               diagnosisCode:
 *                 type: string
 *               procedureCode:
 *                 type: string
 *               amount:
 *                 type: number
 *               description:
 *                 type: string
 *               urgency:
 *                 type: string
 *                 enum: [low, medium, high, emergency]
 *               attachments:
 *                 type: array
 *                 items:
 *                   type: object
 *               metadata:
 *                 type: object
 *     responses:
 *       201:
 *         description: Claim submitted successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.post('/',
  requirePermission(PERMISSIONS.CLAIMS.WRITE),
  validate(claimSchemas.submit),
  asyncHandler(async (req: Request, res: Response) => {
    const {
      policyId,
      providerId,
      patientId,
      serviceDate,
      diagnosisCode,
      procedureCode,
      amount,
      description,
      urgency = 'medium',
      attachments = [],
      metadata = {},
    } = req.body;

    const userId = req.user!.id;
    const claimId = uuidv4();

    // Validate policy exists and is active
    const policyResult = await databaseService.query(
      'SELECT id, holder_id, effective_date, expiry_date, is_active FROM policies WHERE id = $1',
      [policyId],
    );

    if (policyResult.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const policy = policyResult.rows[0];
    if (!policy.is_active) {
      throw new BusinessLogicError('Policy is not active');
    }

    const serviceDateTime = new Date(serviceDate);
    const effectiveDate = new Date(policy.effective_date);
    const expiryDate = new Date(policy.expiry_date);

    if (serviceDateTime < effectiveDate || serviceDateTime > expiryDate) {
      throw new BusinessLogicError('Service date is outside policy coverage period');
    }

    // Validate provider exists and is active
    const providerResult = await databaseService.query(
      'SELECT id, name, is_active FROM providers WHERE id = $1',
      [providerId],
    );

    if (providerResult.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    const provider = providerResult.rows[0];
    if (!provider.is_active) {
      throw new BusinessLogicError('Provider is not active');
    }

    // Validate patient exists
    const patientResult = await databaseService.query(
      'SELECT id FROM users WHERE id = $1 AND role = $2',
      [patientId, 'patient'],
    );

    if (patientResult.rows.length === 0) {
      throw new NotFoundError('Patient');
    }

    // Check for duplicate claims (same patient, provider, procedure, date)
    const duplicateCheck = await databaseService.query(
      `SELECT id FROM claims 
       WHERE patient_id = $1 AND provider_id = $2 AND procedure_code = $3 
       AND service_date = $4 AND status != 'rejected'`,
      [patientId, providerId, procedureCode, serviceDate],
    );

    if (duplicateCheck.rows.length > 0) {
      throw new BusinessLogicError('A similar claim already exists for this service');
    }

    // Calculate claim priority and procedure category
    const priority = calculateClaimPriority(amount, urgency, diagnosisCode);
    const procedureCategory = getProcedureCategory(procedureCode);

    // Start database transaction
    await databaseService.query('BEGIN');

    try {
      // Insert claim into database
      const claimResult = await databaseService.query(
        `INSERT INTO claims (
          id, policy_id, provider_id, patient_id, service_date, diagnosis_code,
          procedure_code, amount, description, urgency, priority, procedure_category,
          status, attachments, metadata, submitted_by, submitted_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
        RETURNING *`,
        [
          claimId, policyId, providerId, patientId, serviceDate, diagnosisCode,
          procedureCode, amount, description, urgency, priority, procedureCategory,
          'submitted', JSON.stringify(attachments), JSON.stringify(metadata), userId,
        ],
      );

      const claim = claimResult.rows[0];

      // Submit claim to blockchain
      try {
        const blockchainResult = await blockchainService.submitClaim(
          claimId,
          Math.round(amount * 100).toString(), // Convert to cents
          providerId,
          patientId,
        );

        // Update claim with blockchain transaction hash
        await databaseService.query(
          'UPDATE claims SET blockchain_tx_hash = $1 WHERE id = $2',
          [blockchainResult, claimId],
        );

        logger.logBlockchainTransaction(
          blockchainResult,
          'ClaimSubmitted',
          0,
          { claimId, amount },
        );

      } catch (blockchainError) {
        logger.logError(blockchainError as Error, 'Blockchain submission failed', {
          claimId,
          amount,
          providerId,
        });

        // Continue with database-only processing for now
        // In production, you might want to queue for retry
      }

      // Commit transaction
      await databaseService.query('COMMIT');

      // Cache claim for quick access
      await redisService.set(`claim:${claimId}`, claim, { ttl: 3600 });

      // Log claim submission
      logger.logClaimActivity('Claim submitted', claimId, userId, {
        amount,
        providerId,
        patientId,
        urgency,
        priority,
      });

      // Trigger fraud detection analysis (async)
      setImmediate(async () => {
        try {
          await blockchainService.analyzeClaim(
            claimId,
            claim.amount.toString(),
            claim.provider_id,
            claim.patient_id,
            JSON.stringify([]),
          );
        } catch (error) {
          logger.logError(error as Error, 'Fraud analysis failed', { claimId });
        }
      });

      res.status(201).json({
        message: 'Claim submitted successfully',
        claim: {
          id: claim.id,
          status: claim.status,
          amount: claim.amount,
          priority: claim.priority,
          submittedAt: claim.submitted_at,
          estimatedProcessingTime: priority === 'high' ? '24 hours' : '3-5 business days',
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
 * /api/claims:
 *   get:
 *     summary: Get claims with filtering and pagination
 *     tags: [Claims]
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
 *         name: status
 *         schema:
 *           type: string
 *           enum: [submitted, under_review, approved, rejected, settled]
 *       - in: query
 *         name: providerId
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: query
 *         name: patientId
 *         schema:
 *           type: string
 *           format: uuid
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
 *       - in: query
 *         name: amountMin
 *         schema:
 *           type: number
 *       - in: query
 *         name: amountMax
 *         schema:
 *           type: number
 *       - in: query
 *         name: urgency
 *         schema:
 *           type: string
 *           enum: [low, medium, high, emergency]
 *     responses:
 *       200:
 *         description: Claims retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/',
  requirePermission(PERMISSIONS.CLAIMS.READ),
  validate(claimSchemas.search, 'query'),
  asyncHandler(async (req: Request, res: Response) => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'submitted_at',
      sortOrder = 'desc',
      status,
      providerId,
      patientId,
      dateFrom,
      dateTo,
      amountMin,
      amountMax,
      urgency,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);
    const user = req.user!;

    // Build WHERE clause based on filters and user role
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    // Role-based filtering
    if (user['role'] === 'patient') {
      conditions.push(`c.patient_id = $${paramIndex++}`);
      params.push(user.id);
    } else if (user['role'] === 'provider') {
      conditions.push(`c.provider_id = $${paramIndex++}`);
      params.push(user.id);
    }

    // Apply filters
    if (status) {
      conditions.push(`c.status = $${paramIndex++}`);
      params.push(status);
    }

    if (providerId) {
      conditions.push(`c.provider_id = $${paramIndex++}`);
      params.push(providerId);
    }

    if (patientId) {
      conditions.push(`c.patient_id = $${paramIndex++}`);
      params.push(patientId);
    }

    if (dateFrom) {
      conditions.push(`c.service_date >= $${paramIndex++}`);
      params.push(dateFrom);
    }

    if (dateTo) {
      conditions.push(`c.service_date <= $${paramIndex++}`);
      params.push(dateTo);
    }

    if (amountMin) {
      conditions.push(`c.amount >= $${paramIndex++}`);
      params.push(amountMin);
    }

    if (amountMax) {
      conditions.push(`c.amount <= $${paramIndex++}`);
      params.push(amountMax);
    }

    if (urgency) {
      conditions.push(`c.urgency = $${paramIndex++}`);
      params.push(urgency);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM claims c
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get claims
    const claimsQuery = `
      SELECT 
        c.id, c.policy_id, c.provider_id, c.patient_id, c.service_date,
        c.diagnosis_code, c.procedure_code, c.amount, c.description,
        c.urgency, c.priority, c.procedure_category, c.status,
        c.submitted_at, c.updated_at, c.blockchain_tx_hash,
        p.name as provider_name,
        u.first_name as patient_first_name,
        u.last_name as patient_last_name,
        pol.policy_number
      FROM claims c
      LEFT JOIN providers p ON c.provider_id = p.id
      LEFT JOIN users u ON c.patient_id = u.id
      LEFT JOIN policies pol ON c.policy_id = pol.id
      ${whereClause}
      ORDER BY c.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const claimsResult = await databaseService.query(claimsQuery, params);

    const claims = claimsResult.rows.map(row => ({
      id: row.id,
      policyId: row.policy_id,
      policyNumber: row.policy_number,
      providerId: row.provider_id,
      providerName: row.provider_name,
      patientId: row.patient_id,
      patientName: `${row.patient_first_name} ${row.patient_last_name}`,
      serviceDate: row.service_date,
      diagnosisCode: row.diagnosis_code,
      procedureCode: row.procedure_code,
      amount: parseFloat(row.amount),
      description: row.description,
      urgency: row.urgency,
      priority: row.priority,
      procedureCategory: row.procedure_category,
      status: row.status,
      submittedAt: row.submitted_at,
      updatedAt: row.updated_at,
      blockchainTxHash: row.blockchain_tx_hash,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      claims,
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
 * /api/claims/{id}:
 *   get:
 *     summary: Get claim by ID
 *     tags: [Claims]
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
 *         description: Claim retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Claim not found
 */
router.get('/:id',
  requirePermission(PERMISSIONS.CLAIMS.READ),
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const user = req.user!;

    // Check cache first
    const cachedClaim = await redisService.get(`claim:${id}`);
    if (cachedClaim) {
      return res.json({ claim: cachedClaim });
    }

    // Build query with role-based access control
    let whereClause = 'WHERE c.id = $1';
    const params = [id];

    if (user['role'] === 'patient') {
      whereClause += ' AND c.patient_id = $2';
      params.push(user.id);
    } else if (user['role'] === 'provider') {
      whereClause += ' AND c.provider_id = $2';
      params.push(user.id);
    }

    const claimQuery = `
      SELECT 
        c.*,
        p.name as provider_name,
        p.npi as provider_npi,
        u.first_name as patient_first_name,
        u.last_name as patient_last_name,
        u.date_of_birth as patient_dob,
        pol.policy_number,
        pol.plan_type,
        pol.coverage_details
      FROM claims c
      LEFT JOIN providers p ON c.provider_id = p.id
      LEFT JOIN users u ON c.patient_id = u.id
      LEFT JOIN policies pol ON c.policy_id = pol.id
      ${whereClause}
    `;

    const result = await databaseService.query(claimQuery, params);

    if (result.rows.length === 0) {
      throw new NotFoundError('Claim');
    }

    const row = result.rows[0];
    const claim = {
      id: row.id,
      policyId: row.policy_id,
      policyNumber: row.policy_number,
      planType: row.plan_type,
      coverageDetails: row.coverage_details,
      providerId: row.provider_id,
      providerName: row.provider_name,
      providerNpi: row.provider_npi,
      patientId: row.patient_id,
      patientName: `${row.patient_first_name} ${row.patient_last_name}`,
      patientDob: row.patient_dob,
      serviceDate: row.service_date,
      diagnosisCode: row.diagnosis_code,
      procedureCode: row.procedure_code,
      amount: parseFloat(row.amount),
      description: row.description,
      urgency: row.urgency,
      priority: row.priority,
      procedureCategory: row.procedure_category,
      status: row.status,
      attachments: row.attachments,
      metadata: row.metadata,
      submittedBy: row.submitted_by,
      submittedAt: row.submitted_at,
      updatedAt: row.updated_at,
      blockchainTxHash: row.blockchain_tx_hash,
      reviewNotes: row.review_notes,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      adjustedAmount: row.adjusted_amount ? parseFloat(row.adjusted_amount) : null,
    };

    // Cache the claim
    await redisService.set(`claim:${id}`, claim, { ttl: 1800 });

    return res.json({ claim });
  }),
);

/**
 * @swagger
 * /api/claims/{id}/review:
 *   post:
 *     summary: Review a claim (approve/reject)
 *     tags: [Claims]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [approved, rejected, pending_review]
 *               reviewNotes:
 *                 type: string
 *               adjustedAmount:
 *                 type: number
 *     responses:
 *       200:
 *         description: Claim reviewed successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Claim not found
 */
router.post('/:id/review',
  requireRole(['medical_director', 'financial_controller', 'claims_processor', 'admin']),
  validate(claimSchemas.review),
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { status, reviewNotes, adjustedAmount } = req.body;
    const reviewerId = req.user!.id;

    // Get current claim
    const claimResult = await databaseService.query(
      'SELECT * FROM claims WHERE id = $1',
      [id],
    );

    if (claimResult.rows.length === 0) {
      throw new NotFoundError('Claim');
    }

    const claim = claimResult.rows[0];

    // Check if claim can be reviewed
    if (!['submitted', 'under_review'].includes(claim.status)) {
      throw new BusinessLogicError('Claim cannot be reviewed in its current status');
    }

    // Validate adjusted amount
    if (adjustedAmount && adjustedAmount > claim.amount) {
      throw new ValidationError('Adjusted amount cannot be greater than original amount');
    }

    // For high-value claims, check if multi-signature approval is required
    const requiresMultiSig = claim.amount > (config.constants.largeClaimThreshold || 50000);

    if (requiresMultiSig && status === 'approved') {
      // Create multi-signature approval request
      try {
        await blockchainService.createApprovalRequest(
            id!,
            ((adjustedAmount || claim.amount) * 100).toString(),
            3,
        );

        // Update claim status to pending approval
        await databaseService.query(
          `UPDATE claims 
           SET status = 'pending_approval', review_notes = $1, reviewed_by = $2, reviewed_at = NOW()
           WHERE id = $3`,
          [reviewNotes, reviewerId, id],
        );

        logger.logClaimActivity('Claim sent for multi-signature approval', id!, reviewerId, {
          originalAmount: claim.amount,
          adjustedAmount: adjustedAmount || claim.amount,
        });

        res.json({
          message: 'Claim sent for multi-signature approval',
          status: 'pending_approval',
          requiresMultiSig: true,
        });
        return;

      } catch (blockchainError) {
        logger.logError(blockchainError as Error, 'Multi-sig approval creation failed', {
          claimId: id,
        });
        throw new BlockchainError('Failed to create approval request');
      }
    }

    // Regular review process
    await databaseService.query('BEGIN');

    try {
      // Update claim
      await databaseService.query(
        `UPDATE claims 
         SET status = $1, review_notes = $2, adjusted_amount = $3, 
             reviewed_by = $4, reviewed_at = NOW(), updated_at = NOW()
         WHERE id = $5`,
        [status, reviewNotes, adjustedAmount, reviewerId, id],
      );

      // If approved, initiate settlement
      if (status === 'approved') {
        const settlementAmount = adjustedAmount || claim.amount;

        try {
          await blockchainService.initiateSettlement(
            id!,
            claim.provider_id,
            (settlementAmount * 100).toString(),
            'USD',
          );

          logger.logClaimActivity('Settlement initiated', id!, reviewerId, {
            amount: settlementAmount,
          });

        } catch (settlementError) {
          logger.logError(settlementError as Error, 'Settlement initiation failed', {
            claimId: id,
            amount: settlementAmount,
          });
          // Continue with approval but log the error
        }
      }

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`claim:${id}`);

      logger.logClaimActivity(`Claim ${status}`, id!, reviewerId, {
        reviewNotes,
        adjustedAmount,
        originalAmount: claim.amount,
      });

      return res.json({
        message: `Claim ${status} successfully`,
        status,
        adjustedAmount: adjustedAmount || claim.amount,
        reviewedAt: new Date().toISOString(),
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/claims/{id}/status:
 *   get:
 *     summary: Get claim status and processing history
 *     tags: [Claims]
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
 *         description: Claim status retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Claim not found
 */
router.get('/:id/status',
  requirePermission(PERMISSIONS.CLAIMS.READ),
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const user = req.user!;

    // Get claim with access control
    let whereClause = 'WHERE c.id = $1';
    const params = [id];

    if (user['role'] === 'patient') {
      whereClause += ' AND c.patient_id = $2';
      params.push(user.id);
    } else if (user['role'] === 'provider') {
      whereClause += ' AND c.provider_id = $2';
      params.push(user.id);
    }

    const claimResult = await databaseService.query(
      `SELECT c.id, c.status, c.submitted_at, c.updated_at, c.amount, 
              c.adjusted_amount, c.urgency, c.priority
       FROM claims c ${whereClause}`,
      params,
    );

    if (claimResult.rows.length === 0) {
      throw new NotFoundError('Claim');
    }

    const claim = claimResult.rows[0];

    // Get audit trail
    const auditResult = await databaseService.query(
      `SELECT action, details, created_at, user_id
       FROM audit_logs 
       WHERE entity_type = 'claim' AND entity_id = $1
       ORDER BY created_at ASC`,
      [id],
    );

    const statusHistory = auditResult.rows.map(row => ({
      action: row.action,
      details: row.details,
      timestamp: row.created_at,
      userId: row.user_id,
    }));

    // Calculate estimated completion time
    let estimatedCompletion = null;
    if (claim.status === 'submitted' || claim.status === 'under_review') {
      const processingTime = claim.priority === 'high' ? 24 : 72; // hours
      estimatedCompletion = new Date(Date.now() + processingTime * 60 * 60 * 1000);
    }

    res.json({
      claimId: claim.id,
      status: claim.status,
      amount: parseFloat(claim.amount),
      adjustedAmount: claim.adjusted_amount ? parseFloat(claim.adjusted_amount) : null,
      urgency: claim.urgency,
      priority: claim.priority,
      submittedAt: claim.submitted_at,
      lastUpdated: claim.updated_at,
      estimatedCompletion,
      statusHistory,
    });
  }),
);

/**
 * @swagger
 * /api/claims/stats:
 *   get:
 *     summary: Get claims statistics
 *     tags: [Claims]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Claims statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/stats',
  requirePermission(PERMISSIONS.ANALYTICS.READ),
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;

    // Build base query with role-based filtering
    let whereClause = '';
    const params: any[] = [];

    if (user['role'] === 'provider') {
      whereClause = 'WHERE provider_id = $1';
      params.push(user.id);
    } else if (user['role'] === 'patient') {
      whereClause = 'WHERE patient_id = $1';
      params.push(user.id);
    }

    // Get overall statistics
    const statsQuery = `
      SELECT 
        COUNT(*) as total_claims,
        COUNT(CASE WHEN status = 'submitted' THEN 1 END) as submitted,
        COUNT(CASE WHEN status = 'under_review' THEN 1 END) as under_review,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected,
        COUNT(CASE WHEN status = 'settled' THEN 1 END) as settled,
        SUM(amount) as total_amount,
        SUM(CASE WHEN status = 'approved' THEN COALESCE(adjusted_amount, amount) ELSE 0 END) as approved_amount,
        AVG(amount) as average_amount
      FROM claims
      ${whereClause}
    `;

    const statsResult = await databaseService.query(statsQuery, params);
    const stats = statsResult.rows[0];

    // Get monthly trends (last 12 months)
    const trendsQuery = `
      SELECT 
        DATE_TRUNC('month', submitted_at) as month,
        COUNT(*) as claims_count,
        SUM(amount) as total_amount
      FROM claims
      ${whereClause}
      ${whereClause ? 'AND' : 'WHERE'} submitted_at >= NOW() - INTERVAL '12 months'
      GROUP BY DATE_TRUNC('month', submitted_at)
      ORDER BY month
    `;

    const trendsResult = await databaseService.query(trendsQuery, params);

    res.json({
      overview: {
        totalClaims: parseInt(stats.total_claims),
        submitted: parseInt(stats.submitted),
        underReview: parseInt(stats.under_review),
        approved: parseInt(stats.approved),
        rejected: parseInt(stats.rejected),
        settled: parseInt(stats.settled),
        totalAmount: parseFloat(stats.total_amount || 0),
        approvedAmount: parseFloat(stats.approved_amount || 0),
        averageAmount: parseFloat(stats.average_amount || 0),
        approvalRate: stats.total_claims > 0 ? (stats.approved / stats.total_claims * 100).toFixed(2) : 0,
      },
      monthlyTrends: trendsResult.rows.map(row => ({
        month: row.month,
        claimsCount: parseInt(row.claims_count),
        totalAmount: parseFloat(row.total_amount),
      })),
    });
  }),
);

export default router;