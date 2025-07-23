import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import redisService from '../services/RedisService';
import { validate, providerSchemas, commonSchemas } from '../middleware/validation';
import { authMiddleware, requirePermission, requireRole, PERMISSIONS } from '../middleware/auth';
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

// Helper function to validate NPI number
const validateNPI = async (npi: string, excludeProviderId?: string): Promise<boolean> => {
  let query = 'SELECT id FROM providers WHERE npi = $1';
  const params = [npi];

  if (excludeProviderId) {
    query += ' AND id != $2';
    params.push(excludeProviderId);
  }

  const result = await databaseService.query(query, params);
  return result.rows.length === 0;
};

// Helper function to validate license
const validateLicense = async (licenseNumber: string, licenseState: string, excludeProviderId?: string): Promise<boolean> => {
  let query = 'SELECT id FROM providers WHERE credentials->\'licenseNumber\' = $1 AND credentials->\'licenseState\' = $2';
  const params = [licenseNumber, licenseState];

  if (excludeProviderId) {
    query += ' AND id != $3';
    params.push(excludeProviderId);
  }

  const result = await databaseService.query(query, params);
  return result.rows.length === 0;
};

// Helper function to calculate provider risk score
const calculateProviderRiskScore = async (providerId: string): Promise<number> => {
  // Get provider statistics
  const statsResult = await databaseService.query(
    `SELECT 
       COUNT(*) as total_claims,
       COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_claims,
       AVG(amount) as avg_claim_amount,
       COUNT(CASE WHEN amount > 10000 THEN 1 END) as high_value_claims
     FROM claims 
     WHERE provider_id = $1 AND submitted_at >= NOW() - INTERVAL '12 months'`,
    [providerId],
  );

  const stats = statsResult.rows[0];
  const totalClaims = parseInt(stats.total_claims);

  if (totalClaims === 0) {
    return 0;
  }

  const rejectionRate = parseInt(stats.rejected_claims) / totalClaims;
  const avgAmount = parseFloat(stats.avg_claim_amount || 0);
  const highValueRate = parseInt(stats.high_value_claims) / totalClaims;

  // Simple risk scoring algorithm
  let riskScore = 0;

  // High rejection rate increases risk
  if (rejectionRate > 0.2) {
    riskScore += 30;
  } else if (rejectionRate > 0.1) {
    riskScore += 15;
  }

  // High average claim amount increases risk
  if (avgAmount > 5000) {
    riskScore += 20;
  } else if (avgAmount > 2000) {
    riskScore += 10;
  }

  // High percentage of high-value claims increases risk
  if (highValueRate > 0.3) {
    riskScore += 25;
  } else if (highValueRate > 0.15) {
    riskScore += 10;
  }

  // Volume factor (very high or very low volume can be risky)
  if (totalClaims > 1000) {
    riskScore += 15;
  } else if (totalClaims < 10) {
    riskScore += 10;
  }

  return Math.min(riskScore, 100);
};

/**
 * @swagger
 * /api/providers:
 *   post:
 *     summary: Register a new healthcare provider
 *     tags: [Providers]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - npi
 *               - taxId
 *               - specialties
 *               - contactInfo
 *               - address
 *               - credentials
 *               - bankingInfo
 *             properties:
 *               name:
 *                 type: string
 *               npi:
 *                 type: string
 *               taxId:
 *                 type: string
 *               specialties:
 *                 type: array
 *                 items:
 *                   type: string
 *               contactInfo:
 *                 type: object
 *               address:
 *                 type: object
 *               credentials:
 *                 type: object
 *               bankingInfo:
 *                 type: object
 *     responses:
 *       201:
 *         description: Provider registered successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       409:
 *         description: Provider already exists
 */
router.post('/',
  requirePermission(PERMISSIONS.PROVIDERS.WRITE),
  validate(providerSchemas.register),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      name,
      npi,
      taxId,
      specialties,
      contactInfo,
      address,
      credentials,
      bankingInfo,
    } = req.body;

    const userId = req.user!.id;
    const providerId = uuidv4();

    // Validate NPI uniqueness
    const isNPIUnique = await validateNPI(npi);
    if (!isNPIUnique) {
      throw new ConflictError('Provider with this NPI already exists');
    }

    // Validate license uniqueness
    const isLicenseUnique = await validateLicense(
      credentials.licenseNumber,
      credentials.licenseState,
    );
    if (!isLicenseUnique) {
      throw new ConflictError('Provider with this license already exists');
    }

    // Check if tax ID is already registered
    const taxIdResult = await databaseService.query(
      'SELECT id FROM providers WHERE tax_id = $1',
      [taxId],
    );
    if (taxIdResult.rows.length > 0) {
      throw new ConflictError('Provider with this Tax ID already exists');
    }

    // Validate license expiry
    const licenseExpiry = new Date(credentials.licenseExpiry);
    if (licenseExpiry <= new Date()) {
      throw new ValidationError('License has expired');
    }

    // Start database transaction
    await databaseService.query('BEGIN');

    try {
      // Insert provider
      const providerResult = await databaseService.query(
        `INSERT INTO providers (
          id, name, npi, tax_id, specialties, contact_info, address,
          credentials, banking_info, status, is_active, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *`,
        [
          providerId,
          name,
          npi,
          taxId,
          JSON.stringify(specialties),
          JSON.stringify(contactInfo),
          JSON.stringify(address),
          JSON.stringify(credentials),
          JSON.stringify(bankingInfo),
          'pending_verification',
          false, // Not active until verified
          userId,
        ],
      );

      const provider = providerResult.rows[0];

      // Create verification tasks
      const verificationTasks = [
        'npi_verification',
        'license_verification',
        'credential_verification',
        'background_check',
      ];

      for (const task of verificationTasks) {
        await databaseService.query(
          `INSERT INTO provider_verifications (id, provider_id, verification_type, status, created_at)
           VALUES ($1, $2, $3, $4, NOW())`,
          [uuidv4(), providerId, task, 'pending'],
        );
      }

      await databaseService.query('COMMIT');

      // Cache provider data
      await redisService.set(`provider:${providerId}`, provider, { ttl: 3600 });

      logger.info('Provider registered', {
        providerId,
        name,
        npi,
        specialties,
        createdBy: userId,
      });

      res.status(201).json({
        message: 'Provider registered successfully. Verification process initiated.',
        provider: {
          id: provider.id,
          name: provider.name,
          npi: provider.npi,
          specialties: provider.specialties,
          status: provider.status,
          createdAt: provider.created_at,
        },
        verificationTasks,
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/providers:
 *   get:
 *     summary: Get providers with filtering and pagination
 *     tags: [Providers]
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
 *           enum: [pending_verification, verified, suspended, rejected]
 *       - in: query
 *         name: specialty
 *         schema:
 *           type: string
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: isActive
 *         schema:
 *           type: boolean
 *     responses:
 *       200:
 *         description: Providers retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/',
  requirePermission(PERMISSIONS.PROVIDERS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      status,
      specialty,
      search,
      isActive,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);

    // Build WHERE clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`p.status = $${paramIndex++}`);
      params.push(status as string);
    }

    if (isActive !== undefined) {
      conditions.push(`p.is_active = $${paramIndex++}`);
      params.push(isActive === 'true');
    }

    if (specialty) {
      conditions.push(`p.specialties::text ILIKE $${paramIndex++}`);
      params.push(`%${specialty}%`);
    }

    if (search) {
      conditions.push(`(
        p.name ILIKE $${paramIndex} OR 
        p.npi ILIKE $${paramIndex} OR 
        p.contact_info->>'email' ILIKE $${paramIndex}
      )`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM providers p
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get providers
    const providersQuery = `
      SELECT 
        p.id, p.name, p.npi, p.specialties, p.contact_info, p.address,
        p.status, p.is_active, p.created_at, p.updated_at, p.risk_score,
        COUNT(c.id) as total_claims,
        COUNT(CASE WHEN c.status = 'approved' THEN 1 END) as approved_claims
      FROM providers p
      LEFT JOIN claims c ON p.id = c.provider_id
      ${whereClause}
      GROUP BY p.id, p.name, p.npi, p.specialties, p.contact_info, p.address,
               p.status, p.is_active, p.created_at, p.updated_at, p.risk_score
      ORDER BY p.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const providersResult = await databaseService.query(providersQuery, params);

    const providers = providersResult.rows.map(row => ({
      id: row.id,
      name: row.name,
      npi: row.npi,
      specialties: row.specialties,
      contactInfo: row.contact_info,
      address: row.address,
      status: row.status,
      isActive: row.is_active,
      riskScore: row.risk_score,
      totalClaims: parseInt(row.total_claims),
      approvedClaims: parseInt(row.approved_claims),
      approvalRate: row.total_claims > 0 ?
        ((row.approved_claims / row.total_claims) * 100).toFixed(2) : 0,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      providers,
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
 * /api/providers/{id}:
 *   get:
 *     summary: Get provider by ID
 *     tags: [Providers]
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
 *         description: Provider retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.get('/:id',
  requirePermission(PERMISSIONS.PROVIDERS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;

    // Check cache first
    const cachedProvider = await redisService.get(`provider:${id}`);
    if (cachedProvider) {
      return res.json({ provider: cachedProvider });
    }

    const providerQuery = `
      SELECT 
        p.*,
        COUNT(c.id) as total_claims,
        COUNT(CASE WHEN c.status = 'approved' THEN 1 END) as approved_claims,
        COUNT(CASE WHEN c.status = 'rejected' THEN 1 END) as rejected_claims,
        SUM(CASE WHEN c.status = 'approved' THEN COALESCE(c.adjusted_amount, c.amount) ELSE 0 END) as total_approved_amount,
        AVG(c.amount) as avg_claim_amount
      FROM providers p
      LEFT JOIN claims c ON p.id = c.provider_id
      WHERE p.id = $1
      GROUP BY p.id
    `;

    const result = await databaseService.query(providerQuery, [id]);

    if (result.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    const row = result.rows[0];

    // Get verification status
    const verificationResult = await databaseService.query(
      'SELECT verification_type, status, verified_at, notes FROM provider_verifications WHERE provider_id = $1',
      [id],
    );

    const verifications = verificationResult.rows.reduce((acc, verification) => {
      acc[verification.verification_type] = {
        status: verification.status,
        verifiedAt: verification.verified_at,
        notes: verification.notes,
      };
      return acc;
    }, {});

    const provider = {
      id: row.id,
      name: row.name,
      npi: row.npi,
      taxId: row.tax_id,
      specialties: row.specialties,
      contactInfo: row.contact_info,
      address: row.address,
      credentials: row.credentials,
      bankingInfo: row.banking_info,
      status: row.status,
      isActive: row.is_active,
      riskScore: row.risk_score,
      verifications,
      statistics: {
        totalClaims: parseInt(row.total_claims),
        approvedClaims: parseInt(row.approved_claims),
        rejectedClaims: parseInt(row.rejected_claims),
        approvalRate: row.total_claims > 0 ?
          ((row.approved_claims / row.total_claims) * 100).toFixed(2) : 0,
        totalApprovedAmount: parseFloat(row.total_approved_amount || 0),
        avgClaimAmount: parseFloat(row.avg_claim_amount || 0),
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };

    // Cache the provider
    await redisService.set(`provider:${id}`, provider, { ttl: 1800 });

    res.json({ provider });
  }),
);

/**
 * @swagger
 * /api/providers/{id}:
 *   put:
 *     summary: Update provider information
 *     tags: [Providers]
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
 *               name:
 *                 type: string
 *               specialties:
 *                 type: array
 *                 items:
 *                   type: string
 *               contactInfo:
 *                 type: object
 *               address:
 *                 type: object
 *               bankingInfo:
 *                 type: object
 *     responses:
 *       200:
 *         description: Provider updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.put('/:id',
  requirePermission(PERMISSIONS.PROVIDERS.WRITE),
  validate(providerSchemas.update),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { name, specialties, contactInfo, address, bankingInfo } = req.body;
    const userId = req.user!.id;

    // Check if provider exists
    const existingProvider = await databaseService.query(
      'SELECT id, status FROM providers WHERE id = $1',
      [id],
    );

    if (existingProvider.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    const provider = existingProvider.rows[0];

    // Build update query
    const updateFields: string[] = [];
    const updateValues: any[] = [];
    let paramIndex = 1;

    if (name) {
      updateFields.push(`name = $${paramIndex++}`);
      updateValues.push(name);
    }

    if (specialties) {
      updateFields.push(`specialties = $${paramIndex++}`);
      updateValues.push(JSON.stringify(specialties));
    }

    if (contactInfo) {
      updateFields.push(`contact_info = $${paramIndex++}`);
      updateValues.push(JSON.stringify(contactInfo));
    }

    if (address) {
      updateFields.push(`address = $${paramIndex++}`);
      updateValues.push(JSON.stringify(address));
    }

    if (bankingInfo) {
      updateFields.push(`banking_info = $${paramIndex++}`);
      updateValues.push(JSON.stringify(bankingInfo));
    }

    if (updateFields.length === 0) {
      throw new ValidationError('No fields to update');
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(id);

    const query = `
      UPDATE providers 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    const result = await databaseService.query(query, updateValues);
    const updatedProvider = result.rows[0];

    // Clear cache
    await redisService.del(`provider:${id}`);

    logger.info('Provider updated', {
      providerId: id,
      updatedFields: Object.keys(req.body),
      updatedBy: userId,
    });

    res.json({
      message: 'Provider updated successfully',
      provider: {
        id: updatedProvider.id,
        name: updatedProvider.name,
        specialties: updatedProvider.specialties,
        contactInfo: updatedProvider.contact_info,
        address: updatedProvider.address,
        updatedAt: updatedProvider.updated_at,
      },
    });
  }),
);

/**
 * @swagger
 * /api/providers/{id}/verify:
 *   post:
 *     summary: Verify provider credentials
 *     tags: [Providers]
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
 *               - verificationType
 *               - status
 *             properties:
 *               verificationType:
 *                 type: string
 *                 enum: [npi_verification, license_verification, credential_verification, background_check]
 *               status:
 *                 type: string
 *                 enum: [verified, failed]
 *               notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Verification updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.post('/:id/verify',
  requireRole(['admin', 'medical_director']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { verificationType, status, notes } = req.body;
    const userId = req.user!.id;

    // Validate input
    const validTypes = ['npi_verification', 'license_verification', 'credential_verification', 'background_check'];
    const validStatuses = ['verified', 'failed'];

    if (!validTypes.includes(verificationType)) {
      throw new ValidationError('Invalid verification type');
    }

    if (!validStatuses.includes(status)) {
      throw new ValidationError('Invalid verification status');
    }

    // Check if provider exists
    const providerResult = await databaseService.query(
      'SELECT id, status FROM providers WHERE id = $1',
      [id],
    );

    if (providerResult.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    await databaseService.query('BEGIN');

    try {
      // Update verification status
      await databaseService.query(
        `UPDATE provider_verifications 
         SET status = $1, verified_at = NOW(), notes = $2, verified_by = $3
         WHERE provider_id = $4 AND verification_type = $5`,
        [status, notes, userId, id, verificationType],
      );

      // Check if all verifications are complete
      const verificationsResult = await databaseService.query(
        'SELECT verification_type, status FROM provider_verifications WHERE provider_id = $1',
        [id],
      );

      const verifications = verificationsResult.rows;
      const allVerified = verifications.every(v => v.status === 'verified');
      const anyFailed = verifications.some(v => v.status === 'failed');

      let providerStatus = 'pending_verification';
      let isActive = false;

      if (allVerified) {
        providerStatus = 'verified';
        isActive = true;
      } else if (anyFailed) {
        providerStatus = 'rejected';
        isActive = false;
      }

      // Update provider status
      await databaseService.query(
        'UPDATE providers SET status = $1, is_active = $2, updated_at = NOW() WHERE id = $3',
        [providerStatus, isActive, id],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`provider:${id}`);

      logger.info('Provider verification updated', {
        providerId: id,
        verificationType,
        status,
        providerStatus,
        verifiedBy: userId,
      });

      res.json({
        message: 'Verification updated successfully',
        verificationType,
        status,
        providerStatus,
        isActive,
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/providers/{id}/suspend:
 *   post:
 *     summary: Suspend or reactivate a provider
 *     tags: [Providers]
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
 *         description: Provider status updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.post('/:id/suspend',
  requirePermission(PERMISSIONS.PROVIDERS.SUSPEND),
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

    // Check if provider exists
    const providerResult = await databaseService.query(
      'SELECT id, name, status, is_active FROM providers WHERE id = $1',
      [id],
    );

    if (providerResult.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    const provider = providerResult.rows[0];

    // Validate action
    if (action === 'suspend' && !provider.is_active) {
      throw new BusinessLogicError('Provider is already suspended');
    }

    if (action === 'reactivate' && provider.is_active) {
      throw new BusinessLogicError('Provider is already active');
    }

    const newStatus = action === 'suspend' ? 'suspended' : 'verified';
    const isActive = action === 'reactivate';

    await databaseService.query('BEGIN');

    try {
      // Update provider status
      await databaseService.query(
        'UPDATE providers SET status = $1, is_active = $2, updated_at = NOW() WHERE id = $3',
        [newStatus, isActive, id],
      );

      // Log the action
      await databaseService.query(
        `INSERT INTO audit_logs (id, entity_type, entity_id, action, details, user_id, created_at)
         VALUES ($1, 'provider', $2, $3, $4, $5, NOW())`,
        [
          uuidv4(),
          id,
          `provider_${action}`,
          JSON.stringify({ reason, previousStatus: provider.status }),
          userId,
        ],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`provider:${id}`);

      logger.info(`Provider ${action}ed`, {
        providerId: id,
        providerName: provider.name,
        action,
        reason,
        actionBy: userId,
      });

      res.json({
        message: `Provider ${action}ed successfully`,
        providerId: id,
        status: newStatus,
        isActive,
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
 * /api/providers/{id}/risk-score:
 *   post:
 *     summary: Update provider risk score
 *     tags: [Providers]
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
 *         description: Risk score updated successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.post('/:id/risk-score',
  requireRole(['admin', 'fraud_analyst']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const userId = req.user!.id;

    // Check if provider exists
    const providerResult = await databaseService.query(
      'SELECT id, name FROM providers WHERE id = $1',
      [id],
    );

    if (providerResult.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    const provider = providerResult.rows[0];

    // Calculate new risk score
    const riskScore = await calculateProviderRiskScore(id!);

    // Update provider risk score
    await databaseService.query(
      'UPDATE providers SET risk_score = $1, updated_at = NOW() WHERE id = $2',
      [riskScore, id],
    );

    // Clear cache
    await redisService.del(`provider:${id}`);

    logger.info('Provider risk score updated', {
      providerId: id,
      providerName: provider.name,
      riskScore,
      updatedBy: userId,
    });

    res.json({
      message: 'Risk score updated successfully',
      providerId: id,
      riskScore,
    });
  }),
);

/**
 * @swagger
 * /api/providers/{id}/claims:
 *   get:
 *     summary: Get claims for a specific provider
 *     tags: [Providers]
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
 *         description: Provider claims retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Provider not found
 */
router.get('/:id/claims',
  requirePermission(PERMISSIONS.CLAIMS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { page = 1, limit = 20, status } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    // Check if provider exists
    const providerResult = await databaseService.query(
      'SELECT id, name FROM providers WHERE id = $1',
      [id],
    );

    if (providerResult.rows.length === 0) {
      throw new NotFoundError('Provider');
    }

    // Build query
    let whereClause = 'WHERE c.provider_id = $1';
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
        c.id, c.patient_id, c.service_date, c.diagnosis_code, c.procedure_code,
        c.amount, c.status, c.urgency, c.priority, c.submitted_at,
        u.first_name as patient_first_name, u.last_name as patient_last_name
      FROM claims c
      LEFT JOIN users u ON c.patient_id = u.id
      ${whereClause}
      ORDER BY c.submitted_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const claimsResult = await databaseService.query(claimsQuery, params);

    const claims = claimsResult.rows.map(row => ({
      id: row.id,
      patientId: row.patient_id,
      patientName: `${row.patient_first_name} ${row.patient_last_name}`,
      serviceDate: row.service_date,
      diagnosisCode: row.diagnosis_code,
      procedureCode: row.procedure_code,
      amount: parseFloat(row.amount),
      status: row.status,
      urgency: row.urgency,
      priority: row.priority,
      submittedAt: row.submitted_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      providerId: id,
      providerName: providerResult.rows[0].name,
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