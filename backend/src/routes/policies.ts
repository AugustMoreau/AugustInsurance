import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import redisService from '../services/RedisService';
import { validate, policySchemas, commonSchemas } from '../middleware/validation';
import { authMiddleware, requirePermission, requireRole, requireOwnership, PERMISSIONS } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import {
  AppError,
  ValidationError,
  NotFoundError,
  ConflictError,
  BusinessLogicError,
} from '../middleware/errorHandler';

const router = Router();

// Apply authentication to all routes
router.use(authMiddleware);

// Helper function to calculate policy premium
const calculatePremium = (policyData: any): number => {
  const {
    coverageType,
    coverageAmount,
    deductible,
    patientAge,
    preExistingConditions,
    riskFactors,
  } = policyData;

  let basePremium = 0;

  // Base premium calculation based on coverage type
  switch (coverageType) {
    case 'basic':
      basePremium = 200;
      break;
    case 'standard':
      basePremium = 400;
      break;
    case 'premium':
      basePremium = 800;
      break;
    case 'comprehensive':
      basePremium = 1200;
      break;
    default:
      basePremium = 400;
  }

  // Coverage amount factor
  const coverageMultiplier = Math.min(coverageAmount / 100000, 10);
  basePremium *= (1 + coverageMultiplier * 0.1);

  // Deductible factor (higher deductible = lower premium)
  const deductibleFactor = Math.max(0.5, 1 - (deductible / 10000));
  basePremium *= deductibleFactor;

  // Age factor
  if (patientAge < 25) {
    basePremium *= 1.2;
  } else if (patientAge > 50) {
    basePremium *= 1.3;
  } else if (patientAge > 65) {
    basePremium *= 1.5;
  }

  // Pre-existing conditions factor
  if (preExistingConditions && preExistingConditions.length > 0) {
    basePremium *= (1 + preExistingConditions.length * 0.15);
  }

  // Risk factors
  if (riskFactors) {
    if (riskFactors.smoking) {
      basePremium *= 1.25;
    }
    if (riskFactors.highRiskOccupation) {
      basePremium *= 1.15;
    }
    if (riskFactors.extremeSports) {
      basePremium *= 1.1;
    }
  }

  return Math.round(basePremium * 100) / 100;
};

// Helper function to validate policy eligibility
const validatePolicyEligibility = async (patientId: string, coverageType: string): Promise<boolean> => {
  // Check if patient already has an active policy of the same type
  const existingPolicy = await databaseService.query(
    `SELECT id FROM policies 
     WHERE patient_id = $1 AND coverage_type = $2 AND status = 'active'`,
    [patientId, coverageType],
  );

  return existingPolicy.rows.length === 0;
};

/**
 * @swagger
 * /api/policies:
 *   post:
 *     summary: Create a new insurance policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - patientId
 *               - coverageType
 *               - coverageAmount
 *               - deductible
 *               - effectiveDate
 *               - expirationDate
 *             properties:
 *               patientId:
 *                 type: string
 *                 format: uuid
 *               coverageType:
 *                 type: string
 *                 enum: [basic, standard, premium, comprehensive]
 *               coverageAmount:
 *                 type: number
 *                 minimum: 1000
 *               deductible:
 *                 type: number
 *                 minimum: 0
 *               effectiveDate:
 *                 type: string
 *                 format: date
 *               expirationDate:
 *                 type: string
 *                 format: date
 *               beneficiaries:
 *                 type: array
 *                 items:
 *                   type: object
 *               preExistingConditions:
 *                 type: array
 *                 items:
 *                   type: string
 *               riskFactors:
 *                 type: object
 *     responses:
 *       201:
 *         description: Policy created successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       409:
 *         description: Policy already exists
 */
router.post('/',
  requirePermission(PERMISSIONS.POLICIES.WRITE),
  validate(policySchemas.create),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      patientId,
      coverageType,
      coverageAmount,
      deductible,
      effectiveDate,
      expirationDate,
      beneficiaries = [],
      preExistingConditions = [],
      riskFactors = {},
    } = req.body;

    const userId = req.user!.id;
    const policyId = uuidv4();

    // Validate patient exists
    const patientResult = await databaseService.query(
      'SELECT id, first_name, last_name, date_of_birth FROM users WHERE id = $1 AND role = $2',
      [patientId, 'patient'],
    );

    if (patientResult.rows.length === 0) {
      throw new NotFoundError('Patient');
    }

    const patient = patientResult.rows[0];

    // Calculate patient age
    const patientAge = Math.floor(
      (new Date().getTime() - new Date(patient.date_of_birth).getTime()) / (365.25 * 24 * 60 * 60 * 1000),
    );

    // Validate policy eligibility
    const isEligible = await validatePolicyEligibility(patientId, coverageType);
    if (!isEligible) {
      throw new ConflictError(`Patient already has an active ${coverageType} policy`);
    }

    // Validate dates
    const effective = new Date(effectiveDate);
    const expiration = new Date(expirationDate);
    const now = new Date();

    if (effective < now) {
      throw new ValidationError('Effective date cannot be in the past');
    }

    if (expiration <= effective) {
      throw new ValidationError('Expiration date must be after effective date');
    }

    // Calculate premium
    const premium = calculatePremium({
      coverageType,
      coverageAmount,
      deductible,
      patientAge,
      preExistingConditions,
      riskFactors,
    });

    // Generate policy number
    const policyNumber = `POL-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;

    await databaseService.query('BEGIN');

    try {
      // Create policy
      const policyResult = await databaseService.query(
        `INSERT INTO policies (
          id, policy_number, patient_id, coverage_type, coverage_amount, deductible,
          premium, effective_date, expiration_date, beneficiaries, 
          pre_existing_conditions, risk_factors, status, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING *`,
        [
          policyId,
          policyNumber,
          patientId,
          coverageType,
          coverageAmount,
          deductible,
          premium,
          effectiveDate,
          expirationDate,
          JSON.stringify(beneficiaries),
          JSON.stringify(preExistingConditions),
          JSON.stringify(riskFactors),
          'pending',
          userId,
        ],
      );

      const policy = policyResult.rows[0];

      // Create initial policy document
      await databaseService.query(
        `INSERT INTO policy_documents (id, policy_id, document_type, document_url, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [
          uuidv4(),
          policyId,
          'policy_certificate',
          `/documents/policies/${policyId}/certificate.pdf`,
        ],
      );

      await databaseService.query('COMMIT');

      // Cache policy data
      await redisService.set(`policy:${policyId}`, policy, { ttl: 3600 });

      logger.info('Policy created', {
        policyId,
        policyNumber,
        patientId,
        coverageType,
        premium,
        createdBy: userId,
      });

      res.status(201).json({
        message: 'Policy created successfully',
        policy: {
          id: policy.id,
          policyNumber: policy.policy_number,
          patientId: policy.patient_id,
          patientName: `${patient.first_name} ${patient.last_name}`,
          coverageType: policy.coverage_type,
          coverageAmount: policy.coverage_amount,
          deductible: policy.deductible,
          premium: policy.premium,
          effectiveDate: policy.effective_date,
          expirationDate: policy.expiration_date,
          status: policy.status,
          createdAt: policy.created_at,
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
 * /api/policies:
 *   get:
 *     summary: Get policies with filtering and pagination
 *     tags: [Policies]
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
 *           enum: [pending, active, suspended, expired, cancelled]
 *       - in: query
 *         name: coverageType
 *         schema:
 *           type: string
 *           enum: [basic, standard, premium, comprehensive]
 *       - in: query
 *         name: patientId
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Policies retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/',
  requirePermission(PERMISSIONS.POLICIES.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      status,
      coverageType,
      patientId,
      search,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);
    const userRole = req.user!['role'];
    const userId = req.user!.id;

    // Build WHERE clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    // Role-based filtering
    if (userRole === 'patient') {
      conditions.push(`p.patient_id = $${paramIndex++}`);
      params.push(userId);
    }

    if (status) {
      conditions.push(`p.status = $${paramIndex++}`);
      params.push(status as string);
    }

    if (coverageType) {
      conditions.push(`p.coverage_type = $${paramIndex++}`);
      params.push(coverageType);
    }

    if (patientId && userRole !== 'patient') {
      conditions.push(`p.patient_id = $${paramIndex++}`);
      params.push(patientId);
    }

    if (search) {
      conditions.push(`(
        p.policy_number ILIKE $${paramIndex} OR 
        u.first_name ILIKE $${paramIndex} OR 
        u.last_name ILIKE $${paramIndex}
      )`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM policies p
      LEFT JOIN users u ON p.patient_id = u.id
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get policies
    const policiesQuery = `
      SELECT 
        p.id, p.policy_number, p.patient_id, p.coverage_type, p.coverage_amount,
        p.deductible, p.premium, p.effective_date, p.expiration_date, p.status,
        p.created_at, p.updated_at,
        u.first_name, u.last_name, u.email,
        COUNT(c.id) as total_claims,
        SUM(CASE WHEN c.status = 'approved' THEN COALESCE(c.adjusted_amount, c.amount) ELSE 0 END) as total_claims_amount
      FROM policies p
      LEFT JOIN users u ON p.patient_id = u.id
      LEFT JOIN claims c ON p.id = c.policy_id
      ${whereClause}
      GROUP BY p.id, p.policy_number, p.patient_id, p.coverage_type, p.coverage_amount,
               p.deductible, p.premium, p.effective_date, p.expiration_date, p.status,
               p.created_at, p.updated_at, u.first_name, u.last_name, u.email
      ORDER BY p.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const policiesResult = await databaseService.query(policiesQuery, params);

    const policies = policiesResult.rows.map(row => ({
      id: row.id,
      policyNumber: row.policy_number,
      patientId: row.patient_id,
      patientName: `${row.first_name} ${row.last_name}`,
      patientEmail: row.email,
      coverageType: row.coverage_type,
      coverageAmount: parseFloat(row.coverage_amount),
      deductible: parseFloat(row.deductible),
      premium: parseFloat(row.premium),
      effectiveDate: row.effective_date,
      expirationDate: row.expiration_date,
      status: row.status,
      totalClaims: parseInt(row.total_claims),
      totalClaimsAmount: parseFloat(row.total_claims_amount || 0),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      policies,
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
 * /api/policies/{id}:
 *   get:
 *     summary: Get policy by ID
 *     tags: [Policies]
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
 *         description: Policy retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 */
router.get('/:id',
  requirePermission(PERMISSIONS.POLICIES.READ),
  requireOwnership('policy'),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;

    // Check cache first
    const cachedPolicy = await redisService.get(`policy:${id}`);
    if (cachedPolicy) {
      return res.json({ policy: cachedPolicy });
    }

    const policyQuery = `
      SELECT 
        p.*,
        u.first_name, u.last_name, u.email, u.date_of_birth,
        COUNT(c.id) as total_claims,
        COUNT(CASE WHEN c.status = 'approved' THEN 1 END) as approved_claims,
        COUNT(CASE WHEN c.status = 'rejected' THEN 1 END) as rejected_claims,
        SUM(CASE WHEN c.status = 'approved' THEN COALESCE(c.adjusted_amount, c.amount) ELSE 0 END) as total_approved_amount,
        SUM(CASE WHEN c.status = 'pending' THEN c.amount ELSE 0 END) as pending_claims_amount
      FROM policies p
      LEFT JOIN users u ON p.patient_id = u.id
      LEFT JOIN claims c ON p.id = c.policy_id
      WHERE p.id = $1
      GROUP BY p.id, u.first_name, u.last_name, u.email, u.date_of_birth
    `;

    const result = await databaseService.query(policyQuery, [id]);

    if (result.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const row = result.rows[0];

    // Get policy documents
    const documentsResult = await databaseService.query(
      'SELECT document_type, document_url, created_at FROM policy_documents WHERE policy_id = $1 ORDER BY created_at DESC',
      [id],
    );

    const documents = documentsResult.rows.map(doc => ({
      type: doc.document_type,
      url: doc.document_url,
      createdAt: doc.created_at,
    }));

    // Calculate remaining coverage
    const totalApprovedAmount = parseFloat(row.total_approved_amount || 0);
    const remainingCoverage = row.coverage_amount - totalApprovedAmount;

    // Calculate policy utilization
    const utilizationRate = row.coverage_amount > 0 ?
      ((totalApprovedAmount / row.coverage_amount) * 100).toFixed(2) : 0;

    const policy = {
      id: row.id,
      policyNumber: row.policy_number,
      patientId: row.patient_id,
      patientInfo: {
        name: `${row.first_name} ${row.last_name}`,
        email: row.email,
        dateOfBirth: row.date_of_birth,
      },
      coverageType: row.coverage_type,
      coverageAmount: parseFloat(row.coverage_amount),
      deductible: parseFloat(row.deductible),
      premium: parseFloat(row.premium),
      effectiveDate: row.effective_date,
      expirationDate: row.expiration_date,
      beneficiaries: row.beneficiaries,
      preExistingConditions: row.pre_existing_conditions,
      riskFactors: row.risk_factors,
      status: row.status,
      statistics: {
        totalClaims: parseInt(row.total_claims),
        approvedClaims: parseInt(row.approved_claims),
        rejectedClaims: parseInt(row.rejected_claims),
        totalApprovedAmount,
        pendingClaimsAmount: parseFloat(row.pending_claims_amount || 0),
        remainingCoverage,
        utilizationRate: parseFloat(utilizationRate as string),
      },
      documents,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };

    // Cache the policy
    await redisService.set(`policy:${id}`, policy, { ttl: 1800 });

    res.json({ policy });
  }),
);

/**
 * @swagger
 * /api/policies/{id}:
 *   put:
 *     summary: Update policy information
 *     tags: [Policies]
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
 *             properties:
 *               coverageAmount:
 *                 type: number
 *                 minimum: 1000
 *               deductible:
 *                 type: number
 *                 minimum: 0
 *               beneficiaries:
 *                 type: array
 *                 items:
 *                   type: object
 *               preExistingConditions:
 *                 type: array
 *                 items:
 *                   type: string
 *               riskFactors:
 *                 type: object
 *     responses:
 *       200:
 *         description: Policy updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 */
router.put('/:id',
  requirePermission(PERMISSIONS.POLICIES.WRITE),
  requireOwnership('policy'),
  validate(policySchemas.update),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { coverageAmount, deductible, beneficiaries, preExistingConditions, riskFactors } = req.body;
    const userId = req.user!.id;

    // Check if policy exists and is modifiable
    const existingPolicy = await databaseService.query(
      'SELECT * FROM policies WHERE id = $1',
      [id],
    );

    if (existingPolicy.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const policy = existingPolicy.rows[0];

    if (policy.status === 'cancelled' || policy.status === 'expired') {
      throw new BusinessLogicError('Cannot update cancelled or expired policy');
    }

    // Get patient info for premium recalculation
    const patientResult = await databaseService.query(
      'SELECT date_of_birth FROM users WHERE id = $1',
      [policy.patient_id],
    );

    const patient = patientResult.rows[0];
    const patientAge = Math.floor(
      (new Date().getTime() - new Date(patient.date_of_birth).getTime()) / (365.25 * 24 * 60 * 60 * 1000),
    );

    // Build update query
    const updateFields: string[] = [];
    const updateValues: any[] = [];
    let paramIndex = 1;
    let recalculatePremium = false;

    if (coverageAmount !== undefined) {
      updateFields.push(`coverage_amount = $${paramIndex++}`);
      updateValues.push(coverageAmount);
      recalculatePremium = true;
    }

    if (deductible !== undefined) {
      updateFields.push(`deductible = $${paramIndex++}`);
      updateValues.push(deductible);
      recalculatePremium = true;
    }

    if (beneficiaries !== undefined) {
      updateFields.push(`beneficiaries = $${paramIndex++}`);
      updateValues.push(JSON.stringify(beneficiaries));
    }

    if (preExistingConditions !== undefined) {
      updateFields.push(`pre_existing_conditions = $${paramIndex++}`);
      updateValues.push(JSON.stringify(preExistingConditions));
      recalculatePremium = true;
    }

    if (riskFactors !== undefined) {
      updateFields.push(`risk_factors = $${paramIndex++}`);
      updateValues.push(JSON.stringify(riskFactors));
      recalculatePremium = true;
    }

    if (updateFields.length === 0) {
      throw new ValidationError('No fields to update');
    }

    // Recalculate premium if necessary
    if (recalculatePremium) {
      const newPremium = calculatePremium({
        coverageType: policy.coverage_type,
        coverageAmount: coverageAmount || policy.coverage_amount,
        deductible: deductible || policy.deductible,
        patientAge,
        preExistingConditions: preExistingConditions || policy.pre_existing_conditions,
        riskFactors: riskFactors || policy.risk_factors,
      });

      updateFields.push(`premium = $${paramIndex++}`);
      updateValues.push(newPremium);
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(id);

    const query = `
      UPDATE policies 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    const result = await databaseService.query(query, updateValues);
    const updatedPolicy = result.rows[0];

    // Clear cache
    await redisService.del(`policy:${id}`);

    logger.info('Policy updated', {
      policyId: id,
      updatedFields: Object.keys(req.body),
      recalculatedPremium: recalculatePremium,
      updatedBy: userId,
    });

    res.json({
      message: 'Policy updated successfully',
      policy: {
        id: updatedPolicy.id,
        policyNumber: updatedPolicy.policy_number,
        coverageAmount: parseFloat(updatedPolicy.coverage_amount),
        deductible: parseFloat(updatedPolicy.deductible),
        premium: parseFloat(updatedPolicy.premium),
        beneficiaries: updatedPolicy.beneficiaries,
        preExistingConditions: updatedPolicy.pre_existing_conditions,
        riskFactors: updatedPolicy.risk_factors,
        updatedAt: updatedPolicy.updated_at,
      },
    });
  }),
);

/**
 * @swagger
 * /api/policies/{id}/activate:
 *   post:
 *     summary: Activate a pending policy
 *     tags: [Policies]
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
 *         description: Policy activated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 *       400:
 *         description: Policy cannot be activated
 */
router.post('/:id/activate',
  requireRole(['admin', 'medical_director']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const userId = req.user!.id;

    // Check if policy exists
    const policyResult = await databaseService.query(
      'SELECT * FROM policies WHERE id = $1',
      [id],
    );

    if (policyResult.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const policy = policyResult.rows[0];

    if (policy.status !== 'pending') {
      throw new BusinessLogicError('Only pending policies can be activated');
    }

    // Check if effective date is valid
    const effectiveDate = new Date(policy.effective_date);
    const now = new Date();

    if (effectiveDate > now) {
      throw new BusinessLogicError('Policy cannot be activated before its effective date');
    }

    // Update policy status
    await databaseService.query(
      'UPDATE policies SET status = $1, updated_at = NOW() WHERE id = $2',
      ['active', id],
    );

    // Clear cache
    await redisService.del(`policy:${id}`);

    logger.info('Policy activated', {
      policyId: id,
      policyNumber: policy.policy_number,
      activatedBy: userId,
    });

    res.json({
      message: 'Policy activated successfully',
      policyId: id,
      status: 'active',
    });
  }),
);

/**
 * @swagger
 * /api/policies/{id}/suspend:
 *   post:
 *     summary: Suspend or reactivate a policy
 *     tags: [Policies]
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
 *               - action
 *               - reason
 *             properties:
 *               action:
 *                 type: string
 *                 enum: [suspend, reactivate]
 *               reason:
 *                 type: string
 *     responses:
 *       200:
 *         description: Policy status updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 */
router.post('/:id/suspend',
  requireRole(['admin', 'medical_director']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { action, reason } = req.body;
    const userId = req.user!.id;

    if (!['suspend', 'reactivate'].includes(action)) {
      throw new ValidationError('Invalid action. Must be suspend or reactivate');
    }

    if (!reason || reason.trim().length === 0) {
      throw new ValidationError('Reason is required');
    }

    // Check if policy exists
    const policyResult = await databaseService.query(
      'SELECT id, policy_number, status FROM policies WHERE id = $1',
      [id],
    );

    if (policyResult.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const policy = policyResult.rows[0];

    // Validate action
    if (action === 'suspend' && policy.status !== 'active') {
      throw new BusinessLogicError('Only active policies can be suspended');
    }

    if (action === 'reactivate' && policy.status !== 'suspended') {
      throw new BusinessLogicError('Only suspended policies can be reactivated');
    }

    const newStatus = action === 'suspend' ? 'suspended' : 'active';

    await databaseService.query('BEGIN');

    try {
      // Update policy status
      await databaseService.query(
        'UPDATE policies SET status = $1, updated_at = NOW() WHERE id = $2',
        [newStatus, id],
      );

      // Log the action
      await databaseService.query(
        `INSERT INTO audit_logs (id, entity_type, entity_id, action, details, user_id, created_at)
         VALUES ($1, 'policy', $2, $3, $4, $5, NOW())`,
        [
          uuidv4(),
          id,
          `policy_${action}`,
          JSON.stringify({ reason, previousStatus: policy.status }),
          userId,
        ],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`policy:${id}`);

      logger.info(`Policy ${action}ed`, {
        policyId: id,
        policyNumber: policy.policy_number,
        action,
        reason,
        actionBy: userId,
      });

      res.json({
        message: `Policy ${action}ed successfully`,
        policyId: id,
        status: newStatus,
        reason,
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/policies/{id}/cancel:
 *   post:
 *     summary: Cancel a policy
 *     tags: [Policies]
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
 *               - reason
 *             properties:
 *               reason:
 *                 type: string
 *               effectiveDate:
 *                 type: string
 *                 format: date
 *     responses:
 *       200:
 *         description: Policy cancelled successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 */
router.post('/:id/cancel',
  requirePermission(PERMISSIONS.POLICIES.WRITE),
  requireOwnership('policy'),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { reason, effectiveDate } = req.body;
    const userId = req.user!.id;

    if (!reason || reason.trim().length === 0) {
      throw new ValidationError('Reason is required');
    }

    // Check if policy exists
    const policyResult = await databaseService.query(
      'SELECT * FROM policies WHERE id = $1',
      [id],
    );

    if (policyResult.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    const policy = policyResult.rows[0];

    if (policy.status === 'cancelled') {
      throw new BusinessLogicError('Policy is already cancelled');
    }

    if (policy.status === 'expired') {
      throw new BusinessLogicError('Cannot cancel an expired policy');
    }

    // Validate effective date
    const cancelDate = effectiveDate ? new Date(effectiveDate) : new Date();
    const now = new Date();

    if (cancelDate < now) {
      throw new ValidationError('Cancellation date cannot be in the past');
    }

    // Check for pending claims
    const pendingClaimsResult = await databaseService.query(
      'SELECT COUNT(*) as count FROM claims WHERE policy_id = $1 AND status IN ($2, $3)',
      [id, 'pending', 'under_review'],
    );

    const pendingClaimsCount = parseInt(pendingClaimsResult.rows[0].count);

    if (pendingClaimsCount > 0) {
      throw new BusinessLogicError(
        `Cannot cancel policy with ${pendingClaimsCount} pending claims. Please resolve all pending claims first.`,
      );
    }

    await databaseService.query('BEGIN');

    try {
      // Update policy status
      await databaseService.query(
        'UPDATE policies SET status = $1, cancellation_date = $2, cancellation_reason = $3, updated_at = NOW() WHERE id = $4',
        ['cancelled', cancelDate, reason, id],
      );

      // Log the cancellation
      await databaseService.query(
        `INSERT INTO audit_logs (id, entity_type, entity_id, action, details, user_id, created_at)
         VALUES ($1, 'policy', $2, $3, $4, $5, NOW())`,
        [
          uuidv4(),
          id,
          'policy_cancelled',
          JSON.stringify({ reason, effectiveDate: cancelDate, previousStatus: policy.status }),
          userId,
        ],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`policy:${id}`);

      logger.info('Policy cancelled', {
        policyId: id,
        policyNumber: policy.policy_number,
        reason,
        effectiveDate: cancelDate,
        cancelledBy: userId,
      });

      res.json({
        message: 'Policy cancelled successfully',
        policyId: id,
        status: 'cancelled',
        cancellationDate: cancelDate,
        reason,
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/policies/{id}/claims:
 *   get:
 *     summary: Get claims for a specific policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
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
 *     responses:
 *       200:
 *         description: Policy claims retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Policy not found
 */
router.get('/:id/claims',
  requirePermission(PERMISSIONS.CLAIMS.READ),
  requireOwnership('policy'),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { page = 1, limit = 20, status } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // Check if policy exists
    const policyResult = await databaseService.query(
      'SELECT id, policy_number FROM policies WHERE id = $1',
      [id],
    );

    if (policyResult.rows.length === 0) {
      throw new NotFoundError('Policy');
    }

    // Build query
    let whereClause = 'WHERE c.policy_id = $1';
    const params: any[] = [id];
    let paramIndex = 2;

    if (status) {
      whereClause += ` AND c.status = $${paramIndex++}`;
      params.push(status as string);
    }

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
        c.id, c.provider_id, c.service_date, c.diagnosis_code, c.procedure_code,
        c.amount, c.adjusted_amount, c.status, c.urgency, c.priority, c.submitted_at,
        p.name as provider_name, p.npi as provider_npi
      FROM claims c
      LEFT JOIN providers p ON c.provider_id = p.id
      ${whereClause}
      ORDER BY c.submitted_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const claimsResult = await databaseService.query(claimsQuery, params);

    const claims = claimsResult.rows.map(row => ({
      id: row.id,
      providerId: row.provider_id,
      providerName: row.provider_name,
      providerNPI: row.provider_npi,
      serviceDate: row.service_date,
      diagnosisCode: row.diagnosis_code,
      procedureCode: row.procedure_code,
      amount: parseFloat(row.amount),
      adjustedAmount: row.adjusted_amount ? parseFloat(row.adjusted_amount) : null,
      status: row.status,
      urgency: row.urgency,
      priority: row.priority,
      submittedAt: row.submitted_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      policyId: id,
      policyNumber: policyResult.rows[0].policy_number,
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

export default router;