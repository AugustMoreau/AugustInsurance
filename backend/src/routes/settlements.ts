import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import redisService from '../services/RedisService';
import blockchainService from '../services/BlockchainService';
import { validate, settlementSchemas, commonSchemas } from '../middleware/validation';
import { authMiddleware, requirePermission, requireRole, PERMISSIONS } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import {
  AppError,
  ValidationError,
  NotFoundError,
  ConflictError,
  BusinessLogicError,
  BlockchainError,
} from '../middleware/errorHandler';

const router = Router();

// Apply authentication to all routes
router.use(authMiddleware);

// Helper function to calculate settlement fees
const calculateSettlementFees = (amount: number, settlementType: string, priority: string): number => {
  let feeRate = 0;

  // Base fee rates
  switch (settlementType) {
    case 'immediate':
      feeRate = 0.025; // 2.5%
      break;
    case 'same_day':
      feeRate = 0.015; // 1.5%
      break;
    case 'next_day':
      feeRate = 0.01; // 1%
      break;
    case 'standard':
      feeRate = 0.005; // 0.5%
      break;
    default:
      feeRate = 0.01;
  }

  // Priority adjustments
  if (priority === 'urgent') {
    feeRate *= 1.5;
  } else if (priority === 'emergency') {
    feeRate *= 2;
  }

  // Calculate fee with minimum and maximum limits
  const calculatedFee = amount * feeRate;
  const minFee = 1.00; // Minimum $1
  const maxFee = 100.00; // Maximum $100

  return Math.max(minFee, Math.min(maxFee, calculatedFee));
};

// Helper function to validate settlement eligibility
const validateSettlementEligibility = async (claimId: string): Promise<any> => {
  const claimResult = await databaseService.query(
    `SELECT c.*, p.banking_info, p.is_active as provider_active, p.status as provider_status
     FROM claims c
     LEFT JOIN providers p ON c.provider_id = p.id
     WHERE c.id = $1`,
    [claimId],
  );

  if (claimResult.rows.length === 0) {
    throw new NotFoundError('Claim');
  }

  const claim = claimResult.rows[0];

  if (claim.status !== 'approved') {
    throw new BusinessLogicError('Only approved claims can be settled');
  }

  if (!claim.provider_active || claim.provider_status !== 'verified') {
    throw new BusinessLogicError('Provider must be active and verified for settlement');
  }

  if (!claim.banking_info) {
    throw new BusinessLogicError('Provider banking information is required for settlement');
  }

  // Check if settlement already exists
  const existingSettlement = await databaseService.query(
    'SELECT id FROM settlements WHERE claim_id = $1 AND status != $2',
    [claimId, 'failed'],
  );

  if (existingSettlement.rows.length > 0) {
    throw new ConflictError('Settlement already exists for this claim');
  }

  return claim;
};

/**
 * @swagger
 * /api/settlements:
 *   post:
 *     summary: Initiate a new settlement
 *     tags: [Settlements]
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
 *               - settlementType
 *               - priority
 *             properties:
 *               claimId:
 *                 type: string
 *                 format: uuid
 *               settlementType:
 *                 type: string
 *                 enum: [immediate, same_day, next_day, standard]
 *               priority:
 *                 type: string
 *                 enum: [normal, urgent, emergency]
 *               notes:
 *                 type: string
 *     responses:
 *       201:
 *         description: Settlement initiated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Claim not found
 *       409:
 *         description: Settlement already exists
 */
router.post('/',
  requirePermission(PERMISSIONS.SETTLEMENTS.WRITE),
  validate(settlementSchemas.initiate),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { claimId, settlementType, priority, notes } = req.body;
    const userId = req.user!.id;
    const settlementId = uuidv4();

    // Validate settlement eligibility
    const claim = await validateSettlementEligibility(claimId);

    // Calculate settlement amount and fees
    const settlementAmount = claim.adjusted_amount || claim.amount;
    const fees = calculateSettlementFees(settlementAmount, settlementType, priority);
    const netAmount = settlementAmount - fees;

    // Calculate expected settlement date
    const now = new Date();
    const expectedDate = new Date(now);

    switch (settlementType) {
      case 'immediate':
        expectedDate.setMinutes(now.getMinutes() + 30);
        break;
      case 'same_day':
        expectedDate.setHours(23, 59, 59, 999);
        break;
      case 'next_day':
        expectedDate.setDate(now.getDate() + 1);
        expectedDate.setHours(17, 0, 0, 0);
        break;
      case 'standard':
        expectedDate.setDate(now.getDate() + 3);
        expectedDate.setHours(17, 0, 0, 0);
        break;
    }

    await databaseService.query('BEGIN');

    try {
      // Create settlement record
      const settlementResult = await databaseService.query(
        `INSERT INTO settlements (
          id, claim_id, provider_id, amount, fees, net_amount, settlement_type,
          priority, status, expected_settlement_date, notes, initiated_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *`,
        [
          settlementId,
          claimId,
          claim.provider_id,
          settlementAmount,
          fees,
          netAmount,
          settlementType,
          priority,
          'pending',
          expectedDate,
          notes,
          userId,
        ],
      );

      const settlement = settlementResult.rows[0];

      // Initiate blockchain settlement
      try {
        const blockchainTxHash = await blockchainService.initiateSettlement(
          settlementId,
          claim.provider_id,
          Math.round(netAmount * 100).toString(), // Convert to cents
          settlementType,
          priority,
        );

        // Update settlement with blockchain transaction hash
        await databaseService.query(
          'UPDATE settlements SET blockchain_tx_hash = $1, status = $2 WHERE id = $3',
          [blockchainTxHash, 'processing', settlementId],
        );

        settlement.blockchain_tx_hash = blockchainTxHash;
        settlement.status = 'processing';

      } catch (blockchainError) {
        logger.error('Blockchain settlement initiation failed', {
          settlementId,
          claimId,
          error: blockchainError,
        });

        // Update settlement status to failed
        await databaseService.query(
          'UPDATE settlements SET status = $1, failure_reason = $2 WHERE id = $3',
          ['failed', 'Blockchain transaction failed', settlementId],
        );

        throw new BlockchainError('Failed to initiate blockchain settlement');
      }

      await databaseService.query('COMMIT');

      // Cache settlement data
      await redisService.set(`settlement:${settlementId}`, settlement, { ttl: 3600 });

      logger.info('Settlement initiated', {
        settlementId,
        claimId,
        providerId: claim.provider_id,
        amount: settlementAmount,
        netAmount,
        settlementType,
        priority,
        initiatedBy: userId,
      });

      res.status(201).json({
        message: 'Settlement initiated successfully',
        settlement: {
          id: settlement.id,
          claimId: settlement.claim_id,
          providerId: settlement.provider_id,
          amount: parseFloat(settlement.amount),
          fees: parseFloat(settlement.fees),
          netAmount: parseFloat(settlement.net_amount),
          settlementType: settlement.settlement_type,
          priority: settlement.priority,
          status: settlement.status,
          expectedSettlementDate: settlement.expected_settlement_date,
          blockchainTxHash: settlement.blockchain_tx_hash,
          createdAt: settlement.created_at,
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
 * /api/settlements:
 *   get:
 *     summary: Get settlements with filtering and pagination
 *     tags: [Settlements]
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
 *           enum: [pending, processing, completed, failed, cancelled]
 *       - in: query
 *         name: settlementType
 *         schema:
 *           type: string
 *           enum: [immediate, same_day, next_day, standard]
 *       - in: query
 *         name: providerId
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: query
 *         name: priority
 *         schema:
 *           type: string
 *           enum: [normal, urgent, emergency]
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
 *         description: Settlements retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/',
  requirePermission(PERMISSIONS.SETTLEMENTS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      status,
      settlementType,
      providerId,
      priority,
      dateFrom,
      dateTo,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);
    const userRole = req.user!['role'];
    const userId = req.user!.id;

    // Build WHERE clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    // Role-based filtering
    if (userRole === 'provider') {
      // Providers can only see their own settlements
      const providerResult = await databaseService.query(
        'SELECT id FROM providers WHERE created_by = $1 OR contact_info->\'email\' = (SELECT email FROM users WHERE id = $1)',
        [userId],
      );

      if (providerResult.rows.length > 0) {
        const providerIds = providerResult.rows.map(row => row.id);
        conditions.push(`s.provider_id = ANY($${paramIndex++})`);
        params.push(providerIds);
      } else {
        // Provider not found, return empty results
        conditions.push('1 = 0');
      }
    }

    if (status) {
      conditions.push(`s.status = $${paramIndex++}`);
      params.push(status);
    }

    if (settlementType) {
      conditions.push(`s.settlement_type = $${paramIndex++}`);
      params.push(settlementType);
    }

    if (providerId && userRole !== 'provider') {
      conditions.push(`s.provider_id = $${paramIndex++}`);
      params.push(providerId);
    }

    if (priority) {
      conditions.push(`s.priority = $${paramIndex++}`);
      params.push(priority);
    }

    if (dateFrom) {
      conditions.push(`s.created_at >= $${paramIndex++}`);
      params.push(dateFrom);
    }

    if (dateTo) {
      conditions.push(`s.created_at <= $${paramIndex++}`);
      params.push(`${dateTo} 23:59:59`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM settlements s
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get settlements
    const settlementsQuery = `
      SELECT 
        s.id, s.claim_id, s.provider_id, s.amount, s.fees, s.net_amount,
        s.settlement_type, s.priority, s.status, s.expected_settlement_date,
        s.actual_settlement_date, s.blockchain_tx_hash, s.created_at, s.updated_at,
        p.name as provider_name, p.npi as provider_npi,
        c.procedure_code, c.diagnosis_code, c.service_date,
        u.first_name as patient_first_name, u.last_name as patient_last_name
      FROM settlements s
      LEFT JOIN providers p ON s.provider_id = p.id
      LEFT JOIN claims c ON s.claim_id = c.id
      LEFT JOIN users u ON c.patient_id = u.id
      ${whereClause}
      ORDER BY s.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const settlementsResult = await databaseService.query(settlementsQuery, params);

    const settlements = settlementsResult.rows.map(row => ({
      id: row.id,
      claimId: row.claim_id,
      providerId: row.provider_id,
      providerName: row.provider_name,
      providerNPI: row.provider_npi,
      patientName: `${row.patient_first_name} ${row.patient_last_name}`,
      procedureCode: row.procedure_code,
      diagnosisCode: row.diagnosis_code,
      serviceDate: row.service_date,
      amount: parseFloat(row.amount),
      fees: parseFloat(row.fees),
      netAmount: parseFloat(row.net_amount),
      settlementType: row.settlement_type,
      priority: row.priority,
      status: row.status,
      expectedSettlementDate: row.expected_settlement_date,
      actualSettlementDate: row.actual_settlement_date,
      blockchainTxHash: row.blockchain_tx_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      settlements,
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
 * /api/settlements/{id}:
 *   get:
 *     summary: Get settlement by ID
 *     tags: [Settlements]
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
 *         description: Settlement retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Settlement not found
 */
router.get('/:id',
  requirePermission(PERMISSIONS.SETTLEMENTS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const userRole = req.user!['role'];
    const userId = req.user!.id;

    // Check cache first
    const cachedSettlement = await redisService.get(`settlement:${id}`);
    if (cachedSettlement) {
      return res.json({ settlement: cachedSettlement });
    }

    let settlementQuery = `
      SELECT 
        s.*,
        p.name as provider_name, p.npi as provider_npi, p.contact_info as provider_contact,
        p.banking_info as provider_banking,
        c.procedure_code, c.diagnosis_code, c.service_date, c.amount as claim_amount,
        c.adjusted_amount as claim_adjusted_amount,
        u.first_name as patient_first_name, u.last_name as patient_last_name,
        pol.policy_number
      FROM settlements s
      LEFT JOIN providers p ON s.provider_id = p.id
      LEFT JOIN claims c ON s.claim_id = c.id
      LEFT JOIN users u ON c.patient_id = u.id
      LEFT JOIN policies pol ON c.policy_id = pol.id
      WHERE s.id = $1
    `;

    const params = [id];

    // Role-based access control
    if (userRole === 'provider') {
      settlementQuery += ' AND (p.created_by = $2 OR p.contact_info->>\'email\' = (SELECT email FROM users WHERE id = $2))';
      params.push(userId);
    }

    const result = await databaseService.query(settlementQuery, params);

    if (result.rows.length === 0) {
      throw new NotFoundError('Settlement');
    }

    const row = result.rows[0];

    // Get settlement history/events
    const historyResult = await databaseService.query(
      `SELECT event_type, event_data, created_at 
       FROM settlement_events 
       WHERE settlement_id = $1 
       ORDER BY created_at ASC`,
      [id],
    );

    const history = historyResult.rows.map(event => ({
      eventType: event.event_type,
      eventData: event.event_data,
      timestamp: event.created_at,
    }));

    const settlement = {
      id: row.id,
      claimId: row.claim_id,
      providerId: row.provider_id,
      providerInfo: {
        name: row.provider_name,
        npi: row.provider_npi,
        contact: row.provider_contact,
        banking: row.provider_banking,
      },
      claimInfo: {
        procedureCode: row.procedure_code,
        diagnosisCode: row.diagnosis_code,
        serviceDate: row.service_date,
        originalAmount: parseFloat(row.claim_amount),
        adjustedAmount: row.claim_adjusted_amount ? parseFloat(row.claim_adjusted_amount) : null,
        policyNumber: row.policy_number,
      },
      patientInfo: {
        name: `${row.patient_first_name} ${row.patient_last_name}`,
      },
      amount: parseFloat(row.amount),
      fees: parseFloat(row.fees),
      netAmount: parseFloat(row.net_amount),
      settlementType: row.settlement_type,
      priority: row.priority,
      status: row.status,
      expectedSettlementDate: row.expected_settlement_date,
      actualSettlementDate: row.actual_settlement_date,
      blockchainTxHash: row.blockchain_tx_hash,
      failureReason: row.failure_reason,
      notes: row.notes,
      history,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };

    // Cache the settlement
    await redisService.set(`settlement:${id}`, settlement, { ttl: 1800 });

    res.json({ settlement });
  }),
);

/**
 * @swagger
 * /api/settlements/{id}/process:
 *   post:
 *     summary: Process a pending settlement
 *     tags: [Settlements]
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
 *             properties:
 *               action:
 *                 type: string
 *                 enum: [approve, reject]
 *               notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Settlement processed successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Settlement not found
 *       400:
 *         description: Invalid settlement status
 */
router.post('/:id/process',
  requireRole(['admin', 'financial_controller']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { action, notes } = req.body;
    const userId = req.user!.id;

    if (!['approve', 'reject'].includes(action)) {
      throw new ValidationError('Invalid action. Must be approve or reject');
    }

    // Get settlement details
    const settlementResult = await databaseService.query(
      'SELECT * FROM settlements WHERE id = $1',
      [id],
    );

    if (settlementResult.rows.length === 0) {
      throw new NotFoundError('Settlement');
    }

    const settlement = settlementResult.rows[0];

    if (settlement.status !== 'pending') {
      throw new BusinessLogicError('Only pending settlements can be processed');
    }

    const newStatus = action === 'approve' ? 'processing' : 'rejected';

    await databaseService.query('BEGIN');

    try {
      if (action === 'approve') {
        // Initiate blockchain settlement if not already done
        if (!settlement.blockchain_tx_hash) {
          try {
            const blockchainTxHash = await blockchainService.initiateSettlement(
              id!,
              settlement.provider_id,
              Math.round(settlement.net_amount * 100).toString(),
              settlement.settlement_type,
              settlement.priority,
            );

            await databaseService.query(
              'UPDATE settlements SET status = $1, blockchain_tx_hash = $2, processed_by = $3, processed_at = NOW(), notes = $4 WHERE id = $5',
              ['processing', blockchainTxHash, userId, notes, id],
            );

          } catch (blockchainError) {
            logger.error('Blockchain settlement processing failed', {
              settlementId: id,
              error: blockchainError,
            });

            await databaseService.query(
              'UPDATE settlements SET status = $1, failure_reason = $2, processed_by = $3, processed_at = NOW() WHERE id = $4',
              ['failed', 'Blockchain transaction failed', userId, id],
            );

            throw new BlockchainError('Failed to process blockchain settlement');
          }
        } else {
          // Update status to processing
          await databaseService.query(
            'UPDATE settlements SET status = $1, processed_by = $2, processed_at = NOW(), notes = $3 WHERE id = $4',
            ['processing', userId, notes, id],
          );
        }
      } else {
        // Reject settlement
        await databaseService.query(
          'UPDATE settlements SET status = $1, failure_reason = $2, processed_by = $3, processed_at = NOW() WHERE id = $4',
          ['rejected', notes || 'Settlement rejected by administrator', userId, id],
        );
      }

      // Log settlement event
      await databaseService.query(
        `INSERT INTO settlement_events (id, settlement_id, event_type, event_data, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [
          uuidv4(),
          id,
          `settlement_${action}d`,
          JSON.stringify({ processedBy: userId, notes, previousStatus: settlement.status }),
        ],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`settlement:${id}`);

      logger.info(`Settlement ${action}d`, {
        settlementId: id,
        action,
        processedBy: userId,
        notes,
      });

      res.json({
        message: `Settlement ${action}d successfully`,
        settlementId: id,
        status: newStatus,
        processedBy: userId,
        processedAt: new Date().toISOString(),
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/settlements/{id}/cancel:
 *   post:
 *     summary: Cancel a settlement
 *     tags: [Settlements]
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
 *     responses:
 *       200:
 *         description: Settlement cancelled successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Settlement not found
 *       400:
 *         description: Settlement cannot be cancelled
 */
router.post('/:id/cancel',
  requireRole(['admin', 'financial_controller']),
  asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { reason } = req.body;
    const userId = req.user!.id;

    if (!reason || reason.trim().length === 0) {
      throw new ValidationError('Cancellation reason is required');
    }

    // Get settlement details
    const settlementResult = await databaseService.query(
      'SELECT * FROM settlements WHERE id = $1',
      [id],
    );

    if (settlementResult.rows.length === 0) {
      throw new NotFoundError('Settlement');
    }

    const settlement = settlementResult.rows[0];

    if (!['pending', 'processing'].includes(settlement.status)) {
      throw new BusinessLogicError('Only pending or processing settlements can be cancelled');
    }

    await databaseService.query('BEGIN');

    try {
      // Update settlement status
      await databaseService.query(
        'UPDATE settlements SET status = $1, failure_reason = $2, cancelled_by = $3, cancelled_at = NOW() WHERE id = $4',
        ['cancelled', reason, userId, id],
      );

      // Log cancellation event
      await databaseService.query(
        `INSERT INTO settlement_events (id, settlement_id, event_type, event_data, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [
          uuidv4(),
          id,
          'settlement_cancelled',
          JSON.stringify({ cancelledBy: userId, reason, previousStatus: settlement.status }),
        ],
      );

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`settlement:${id}`);

      logger.info('Settlement cancelled', {
        settlementId: id,
        reason,
        cancelledBy: userId,
        previousStatus: settlement.status,
      });

      res.json({
        message: 'Settlement cancelled successfully',
        settlementId: id,
        status: 'cancelled',
        reason,
        cancelledBy: userId,
        cancelledAt: new Date().toISOString(),
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/settlements/batch:
 *   post:
 *     summary: Process multiple settlements in batch
 *     tags: [Settlements]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - claimIds
 *               - settlementType
 *               - priority
 *             properties:
 *               claimIds:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uuid
 *               settlementType:
 *                 type: string
 *                 enum: [immediate, same_day, next_day, standard]
 *               priority:
 *                 type: string
 *                 enum: [normal, urgent, emergency]
 *               notes:
 *                 type: string
 *     responses:
 *       201:
 *         description: Batch settlements initiated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.post('/batch',
  requireRole(['admin', 'financial_controller']),
  asyncHandler(async (req: Request, res: Response) => {
    const { claimIds, settlementType, priority, notes } = req.body;
    const userId = req.user!.id;

    if (!Array.isArray(claimIds) || claimIds.length === 0) {
      throw new ValidationError('claimIds must be a non-empty array');
    }

    if (claimIds.length > 100) {
      throw new ValidationError('Maximum 100 claims can be processed in a single batch');
    }

    const results: {
      successful: Array<{
        claimId: any;
        settlementId: string;
        amount: number;
        netAmount: number;
        status: any;
      }>;
      failed: Array<{
        claimId: any;
        error: string;
      }>;
    } = {
      successful: [],
      failed: [],
    };

    await databaseService.query('BEGIN');

    try {
      for (const claimId of claimIds) {
        try {
          // Validate settlement eligibility
          const claim = await validateSettlementEligibility(claimId);

          const settlementId = uuidv4();
          const settlementAmount = claim.adjusted_amount || claim.amount;
          const fees = calculateSettlementFees(settlementAmount, settlementType, priority);
          const netAmount = settlementAmount - fees;

          // Calculate expected settlement date
          const now = new Date();
          const expectedDate = new Date(now);

          switch (settlementType) {
            case 'immediate':
              expectedDate.setMinutes(now.getMinutes() + 30);
              break;
            case 'same_day':
              expectedDate.setHours(23, 59, 59, 999);
              break;
            case 'next_day':
              expectedDate.setDate(now.getDate() + 1);
              expectedDate.setHours(17, 0, 0, 0);
              break;
            case 'standard':
              expectedDate.setDate(now.getDate() + 3);
              expectedDate.setHours(17, 0, 0, 0);
              break;
          }

          // Create settlement record
          const settlementResult = await databaseService.query(
            `INSERT INTO settlements (
              id, claim_id, provider_id, amount, fees, net_amount, settlement_type,
              priority, status, expected_settlement_date, notes, initiated_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *`,
            [
              settlementId,
              claimId,
              claim.provider_id,
              settlementAmount,
              fees,
              netAmount,
              settlementType,
              priority,
              'pending',
              expectedDate,
              notes,
              userId,
            ],
          );

          const settlement = settlementResult.rows[0];

          results.successful.push({
            claimId,
            settlementId,
            amount: parseFloat(settlement.amount),
            netAmount: parseFloat(settlement.net_amount),
            status: settlement.status,
          });

        } catch (error) {
          results.failed.push({
            claimId,
            error: (error as Error).message,
          });
        }
      }

      await databaseService.query('COMMIT');

      logger.info('Batch settlements processed', {
        totalClaims: claimIds.length,
        successful: results.successful.length,
        failed: results.failed.length,
        settlementType,
        priority,
        initiatedBy: userId,
      });

      res.status(201).json({
        message: 'Batch settlements processed',
        summary: {
          total: claimIds.length,
          successful: results.successful.length,
          failed: results.failed.length,
        },
        results,
      });

    } catch (error) {
      await databaseService.query('ROLLBACK');
      throw error;
    }
  }),
);

/**
 * @swagger
 * /api/settlements/statistics:
 *   get:
 *     summary: Get settlement statistics
 *     tags: [Settlements]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [today, week, month, quarter, year]
 *           default: month
 *       - in: query
 *         name: providerId
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Settlement statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/statistics',
  requirePermission(PERMISSIONS.SETTLEMENTS.READ),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { period = 'month', providerId } = req.query;
    const userRole = req.user!['role'];
    const userId = req.user!.id;

    // Calculate date range based on period
    const now = new Date();
    const startDate = new Date();

    switch (period) {
      case 'today':
        startDate.setHours(0, 0, 0, 0);
        break;
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
    const conditions = ['s.created_at >= $1'];
    const params: any[] = [startDate];
    let paramIndex = 2;

    // Role-based filtering
    if (userRole === 'provider') {
      const providerResult = await databaseService.query(
        'SELECT id FROM providers WHERE created_by = $1 OR contact_info->\'email\' = (SELECT email FROM users WHERE id = $1)',
        [userId],
      );

      if (providerResult.rows.length > 0) {
        const providerIds = providerResult.rows.map(row => row.id);
        conditions.push(`s.provider_id = ANY($${paramIndex++})`);
        params.push(providerIds);
      } else {
        // Provider not found, return empty statistics
        return res.json({
          period,
          statistics: {
            totalSettlements: 0,
            totalAmount: 0,
            totalFees: 0,
            totalNetAmount: 0,
            averageAmount: 0,
            statusBreakdown: {},
            typeBreakdown: {},
            priorityBreakdown: {},
          },
        });
      }
    }

    if (providerId && userRole !== 'provider') {
      conditions.push(`s.provider_id = $${paramIndex++}`);
      params.push(providerId);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Get overall statistics
    const statsQuery = `
      SELECT 
        COUNT(*) as total_settlements,
        COALESCE(SUM(amount), 0) as total_amount,
        COALESCE(SUM(fees), 0) as total_fees,
        COALESCE(SUM(net_amount), 0) as total_net_amount,
        COALESCE(AVG(amount), 0) as average_amount
      FROM settlements s
      ${whereClause}
    `;

    const statsResult = await databaseService.query(statsQuery, params);
    const stats = statsResult.rows[0];

    // Get status breakdown
    const statusQuery = `
      SELECT status, COUNT(*) as count, COALESCE(SUM(net_amount), 0) as total_amount
      FROM settlements s
      ${whereClause}
      GROUP BY status
    `;

    const statusResult = await databaseService.query(statusQuery, params);
    const statusBreakdown = statusResult.rows.reduce((acc, row) => {
      acc[row.status] = {
        count: parseInt(row.count),
        totalAmount: parseFloat(row.total_amount),
      };
      return acc;
    }, {});

    // Get settlement type breakdown
    const typeQuery = `
      SELECT settlement_type, COUNT(*) as count, COALESCE(SUM(net_amount), 0) as total_amount
      FROM settlements s
      ${whereClause}
      GROUP BY settlement_type
    `;

    const typeResult = await databaseService.query(typeQuery, params);
    const typeBreakdown = typeResult.rows.reduce((acc, row) => {
      acc[row.settlement_type] = {
        count: parseInt(row.count),
        totalAmount: parseFloat(row.total_amount),
      };
      return acc;
    }, {});

    // Get priority breakdown
    const priorityQuery = `
      SELECT priority, COUNT(*) as count, COALESCE(SUM(net_amount), 0) as total_amount
      FROM settlements s
      ${whereClause}
      GROUP BY priority
    `;

    const priorityResult = await databaseService.query(priorityQuery, params);
    const priorityBreakdown = priorityResult.rows.reduce((acc, row) => {
      acc[row.priority] = {
        count: parseInt(row.count),
        totalAmount: parseFloat(row.total_amount),
      };
      return acc;
    }, {});

    res.json({
      period,
      dateRange: {
        from: startDate,
        to: now,
      },
      statistics: {
        totalSettlements: parseInt(stats.total_settlements),
        totalAmount: parseFloat(stats.total_amount),
        totalFees: parseFloat(stats.total_fees),
        totalNetAmount: parseFloat(stats.total_net_amount),
        averageAmount: parseFloat(stats.average_amount),
        statusBreakdown,
        typeBreakdown,
        priorityBreakdown,
      },
    });
  }),
);

export default router;