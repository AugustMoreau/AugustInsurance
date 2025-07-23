import type { Request, Response } from 'express';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import * as Joi from 'joi';
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

// Helper function to determine required approvers based on amount and type
const getRequiredApprovers = (amount: number, type: 'claim' | 'settlement'): string[] => {
  const approvers = [];

  if (amount >= 100000) {
    // Very high value - requires all senior roles
    approvers.push('medical_director', 'financial_controller', 'admin');
  } else if (amount >= 50000) {
    // High value - requires medical director and financial controller
    approvers.push('medical_director', 'financial_controller');
  } else if (amount >= 25000) {
    // Medium-high value - requires medical director or financial controller
    approvers.push('medical_director');
  }

  // For settlements, always require financial controller
  if (type === 'settlement' && amount >= 10000 && !approvers.includes('financial_controller')) {
    approvers.push('financial_controller');
  }

  return approvers;
};

// Helper function to check if user can approve based on role
const canUserApprove = (userRole: string, requiredApprovers: string[]): boolean => {
  return requiredApprovers.includes(userRole) || userRole === 'admin';
};

// Helper function to calculate approval deadline
const calculateApprovalDeadline = (amount: number, urgency: string): Date => {
  const now = new Date();
  let hoursToAdd = 72; // Default 3 days

  if (urgency === 'urgent') {
    hoursToAdd = 24; // 1 day for urgent
  } else if (urgency === 'high') {
    hoursToAdd = 48; // 2 days for high priority
  } else if (amount >= 100000) {
    hoursToAdd = 120; // 5 days for very high amounts
  }

  return new Date(now.getTime() + hoursToAdd * 60 * 60 * 1000);
};

/**
 * @swagger
 * /api/multisig/approvals:
 *   post:
 *     summary: Create a new multi-signature approval request
 *     tags: [Multi-Signature Approvals]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - entityType
 *               - entityId
 *               - amount
 *               - description
 *             properties:
 *               entityType:
 *                 type: string
 *                 enum: [claim, settlement]
 *               entityId:
 *                 type: string
 *                 format: uuid
 *               amount:
 *                 type: number
 *                 minimum: 0
 *               description:
 *                 type: string
 *                 maxLength: 1000
 *               urgency:
 *                 type: string
 *                 enum: [low, normal, high, urgent]
 *                 default: normal
 *               metadata:
 *                 type: object
 *     responses:
 *       201:
 *         description: Approval request created successfully
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Entity not found
 */
router.post('/approvals',
  requireRole(['admin', 'claims_processor', 'medical_director', 'financial_controller']),
  validate(Joi.object({
    entityType: Joi.string().valid('claim', 'settlement').required(),
    entityId: commonSchemas.id,
    amount: commonSchemas.amount,
    description: Joi.string().max(1000).required(),
    urgency: Joi.string().valid('low', 'medium', 'high', 'emergency').required(),
    metadata: Joi.object().optional(),
  })),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { entityType, entityId, amount, description, urgency = 'normal', metadata = {} } = req.body;
    const userId = req.user!.id;

    // Verify entity exists
    let entityQuery = '';
    if (entityType === 'claim') {
      entityQuery = 'SELECT id, status, amount FROM claims WHERE id = $1';
    } else if (entityType === 'settlement') {
      entityQuery = 'SELECT id, status, amount FROM settlements WHERE id = $1';
    }

    const entityResult = await databaseService.query(entityQuery, [entityId]);
    if (entityResult.rows.length === 0) {
      throw new NotFoundError(`${entityType.charAt(0).toUpperCase() + entityType.slice(1)}`);
    }

    const entity = entityResult.rows[0];

    // Check if entity is in a state that requires approval
    if (entityType === 'claim' && !['pending_review', 'under_review'].includes(entity.status)) {
      throw new BusinessLogicError('Claim is not in a state that requires approval');
    }
    if (entityType === 'settlement' && !['pending', 'processing'].includes(entity.status)) {
      throw new BusinessLogicError('Settlement is not in a state that requires approval');
    }

    // Check if approval request already exists
    const existingApprovalResult = await databaseService.query(
      'SELECT id FROM multisig_approvals WHERE entity_type = $1 AND entity_id = $2 AND status = $3',
      [entityType, entityId, 'pending'],
    );

    if (existingApprovalResult.rows.length > 0) {
      throw new BusinessLogicError('Approval request already exists for this entity');
    }

    const approvalId = uuidv4();
    const requiredApprovers = getRequiredApprovers(amount, entityType as 'claim' | 'settlement');
    const approvalDeadline = calculateApprovalDeadline(amount, urgency);

    await databaseService.query('BEGIN');

    try {
      // Create approval request
      const approvalResult = await databaseService.query(
        `INSERT INTO multisig_approvals (
          id, entity_type, entity_id, amount, description, required_approvers,
          approval_threshold, urgency, deadline, metadata, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *`,
        [
          approvalId,
          entityType,
          entityId,
          amount,
          description,
          JSON.stringify(requiredApprovers),
          requiredApprovers.length,
          urgency,
          approvalDeadline,
          JSON.stringify(metadata),
          userId,
        ],
      );

      const approval = approvalResult.rows[0];

      // Create blockchain approval request
      try {
        await blockchainService.createApprovalRequest(
          approvalId,
          entityType,
          entityId,
          amount,
        );
      } catch (blockchainError) {
        logger.warn('Failed to create blockchain approval request', {
          approvalId,
          error: (blockchainError as Error).message,
        });
        // Continue without blockchain - can be retried later
      }

      // Update entity status to indicate pending approval
      if (entityType === 'claim') {
        await databaseService.query(
          'UPDATE claims SET status = $1 WHERE id = $2',
          ['pending_approval', entityId],
        );
      } else if (entityType === 'settlement') {
        await databaseService.query(
          'UPDATE settlements SET status = $1 WHERE id = $2',
          ['pending_approval', entityId],
        );
      }

      await databaseService.query('COMMIT');

      // Cache approval request
      await redisService.set(`approval:${approvalId}`, approval, { ttl: 3600 });

      // Send notifications to required approvers
      const approverUsersResult = await databaseService.query(
        'SELECT id, email, first_name, last_name FROM users WHERE role = ANY($1) AND is_active = true',
        [requiredApprovers],
      );

      for (const approver of approverUsersResult.rows) {
        // Create notification
        await databaseService.query(
          `INSERT INTO notifications (id, user_id, type, title, message, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            uuidv4(),
            approver.id,
            'approval_required',
            `Approval Required: ${entityType.charAt(0).toUpperCase() + entityType.slice(1)}`,
            `A ${entityType} requiring approval has been submitted. Amount: $${amount.toLocaleString()}`,
            JSON.stringify({ approvalId, entityType, entityId, amount, urgency }),
          ],
        );
      }

      logger.info('Multi-signature approval request created', {
        approvalId,
        entityType,
        entityId,
        amount,
        requiredApprovers,
        urgency,
        createdBy: userId,
      });

      res.status(201).json({
        message: 'Approval request created successfully',
        approval: {
          id: approval.id,
          entityType: approval.entity_type,
          entityId: approval.entity_id,
          amount: parseFloat(approval.amount),
          description: approval.description,
          requiredApprovers: approval.required_approvers,
          approvalThreshold: approval.approval_threshold,
          urgency: approval.urgency,
          deadline: approval.deadline,
          status: approval.status,
          createdAt: approval.created_at,
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
 * /api/multisig/approvals:
 *   get:
 *     summary: Get approval requests with filtering
 *     tags: [Multi-Signature Approvals]
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
 *           enum: [pending, approved, rejected, expired]
 *       - in: query
 *         name: entityType
 *         schema:
 *           type: string
 *           enum: [claim, settlement]
 *       - in: query
 *         name: urgency
 *         schema:
 *           type: string
 *           enum: [low, normal, high, urgent]
 *       - in: query
 *         name: assignedToMe
 *         schema:
 *           type: boolean
 *           default: false
 *     responses:
 *       200:
 *         description: Approval requests retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/approvals',
  requireRole(['admin', 'medical_director', 'financial_controller', 'claims_processor']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc',
      status,
      entityType,
      urgency,
      assignedToMe = false,
    } = req.query;

    const offset = (Number(page) - 1) * Number(limit);
    const userRole = req.user!['role'];

    // Build WHERE clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`ma.status = $${paramIndex++}`);
      params.push(status);
    }

    if (entityType) {
      conditions.push(`ma.entity_type = $${paramIndex++}`);
      params.push(entityType);
    }

    if (urgency) {
      conditions.push(`ma.urgency = $${paramIndex++}`);
      params.push(urgency);
    }

    // Filter by assignments if requested
    if (assignedToMe === 'true') {
      conditions.push(`ma.required_approvers::jsonb ? $${paramIndex++}`);
      params.push(userRole);
    }

    // Non-admin users can only see approvals they can act on
    if (userRole !== 'admin') {
      if (!assignedToMe) {
        conditions.push(`ma.required_approvers::jsonb ? $${paramIndex++}`);
        params.push(userRole);
      }
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM multisig_approvals ma
      ${whereClause}
    `;

    const countResult = await databaseService.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);

    // Get approval requests
    const approvalsQuery = `
      SELECT 
        ma.*,
        u.first_name as creator_first_name, u.last_name as creator_last_name,
        COUNT(av.id) as vote_count,
        COUNT(CASE WHEN av.vote = 'approve' THEN 1 END) as approve_count,
        COUNT(CASE WHEN av.vote = 'reject' THEN 1 END) as reject_count
      FROM multisig_approvals ma
      LEFT JOIN users u ON ma.created_by = u.id
      LEFT JOIN approval_votes av ON ma.id = av.approval_id
      ${whereClause}
      GROUP BY ma.id, u.first_name, u.last_name
      ORDER BY ma.${sortBy} ${sortOrder}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(Number(limit), offset);

    const approvalsResult = await databaseService.query(approvalsQuery, params);

    const approvals = approvalsResult.rows.map(row => ({
      id: row.id,
      entityType: row.entity_type,
      entityId: row.entity_id,
      amount: parseFloat(row.amount),
      description: row.description,
      requiredApprovers: row.required_approvers,
      approvalThreshold: row.approval_threshold,
      urgency: row.urgency,
      deadline: row.deadline,
      status: row.status,
      createdBy: {
        name: `${row.creator_first_name} ${row.creator_last_name}`,
      },
      voteCount: parseInt(row.vote_count),
      approveCount: parseInt(row.approve_count),
      rejectCount: parseInt(row.reject_count),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));

    const totalPages = Math.ceil(total / Number(limit));

    res.json({
      approvals,
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
 * /api/multisig/approvals/{id}:
 *   get:
 *     summary: Get detailed approval request by ID
 *     tags: [Multi-Signature Approvals]
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
 *         description: Approval request retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Approval request not found
 */
router.get('/approvals/:id',
  requireRole(['admin', 'medical_director', 'financial_controller', 'claims_processor']),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const userRole = req.user!['role'];

    // Check cache first
    const cachedApproval = await redisService.get(`approval_detail:${id}`);
    if (cachedApproval) {
      return res.json({ approval: cachedApproval });
    }

    const approvalQuery = `
      SELECT 
        ma.*,
        u.first_name as creator_first_name, u.last_name as creator_last_name, u.email as creator_email
      FROM multisig_approvals ma
      LEFT JOIN users u ON ma.created_by = u.id
      WHERE ma.id = $1
    `;

    const approvalResult = await databaseService.query(approvalQuery, [id]);

    if (approvalResult.rows.length === 0) {
      throw new NotFoundError('Approval request');
    }

    const row = approvalResult.rows[0];

    // Check if user can view this approval
    if (userRole !== 'admin') {
      const requiredApprovers = row.required_approvers;
      if (!requiredApprovers.includes(userRole)) {
        throw new BusinessLogicError('You do not have permission to view this approval request');
      }
    }

    // Get votes
    const votesResult = await databaseService.query(
      `SELECT 
         av.*, u.first_name, u.last_name, u.role
       FROM approval_votes av
       LEFT JOIN users u ON av.voter_id = u.id
       WHERE av.approval_id = $1
       ORDER BY av.created_at`,
      [id],
    );

    const votes = votesResult.rows.map(vote => ({
      id: vote.id,
      vote: vote.vote,
      comment: vote.comment,
      voter: {
        name: `${vote.first_name} ${vote.last_name}`,
        role: vote.role,
      },
      createdAt: vote.created_at,
    }));

    // Get entity details
    let entityDetails = null;
    if (row.entity_type === 'claim') {
      const claimResult = await databaseService.query(
        `SELECT c.*, p.name as provider_name, u.first_name as patient_first_name, u.last_name as patient_last_name
         FROM claims c
         LEFT JOIN providers p ON c.provider_id = p.id
         LEFT JOIN users u ON c.patient_id = u.id
         WHERE c.id = $1`,
        [row.entity_id],
      );

      if (claimResult.rows.length > 0) {
        const claim = claimResult.rows[0];
        entityDetails = {
          type: 'claim',
          id: claim.id,
          amount: parseFloat(claim.amount),
          procedureCode: claim.procedure_code,
          diagnosisCode: claim.diagnosis_code,
          serviceDate: claim.service_date,
          status: claim.status,
          provider: claim.provider_name,
          patient: `${claim.patient_first_name} ${claim.patient_last_name}`,
        };
      }
    } else if (row.entity_type === 'settlement') {
      const settlementResult = await databaseService.query(
        `SELECT s.*, p.name as provider_name
         FROM settlements s
         LEFT JOIN providers p ON s.provider_id = p.id
         WHERE s.id = $1`,
        [row.entity_id],
      );

      if (settlementResult.rows.length > 0) {
        const settlement = settlementResult.rows[0];
        entityDetails = {
          type: 'settlement',
          id: settlement.id,
          amount: parseFloat(settlement.amount),
          settlementType: settlement.settlement_type,
          status: settlement.status,
          provider: settlement.provider_name,
          expectedDate: settlement.expected_settlement_date,
        };
      }
    }

    const approval = {
      id: row.id,
      entityType: row.entity_type,
      entityId: row.entity_id,
      amount: parseFloat(row.amount),
      description: row.description,
      requiredApprovers: row.required_approvers,
      approvalThreshold: row.approval_threshold,
      urgency: row.urgency,
      deadline: row.deadline,
      status: row.status,
      metadata: row.metadata,
      createdBy: {
        name: `${row.creator_first_name} ${row.creator_last_name}`,
        email: row.creator_email,
      },
      entityDetails,
      votes,
      votesSummary: {
        total: votes.length,
        approve: votes.filter(v => v.vote === 'approve').length,
        reject: votes.filter(v => v.vote === 'reject').length,
        required: row.approval_threshold,
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };

    // Cache the detailed approval
    await redisService.set(`approval_detail:${id}`, approval, { ttl: 1800 });

    res.json({ approval });
  }),
);

/**
 * @swagger
 * /api/multisig/approvals/{id}/vote:
 *   post:
 *     summary: Vote on an approval request
 *     tags: [Multi-Signature Approvals]
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
 *               - vote
 *             properties:
 *               vote:
 *                 type: string
 *                 enum: [approve, reject]
 *               comment:
 *                 type: string
 *                 maxLength: 500
 *     responses:
 *       200:
 *         description: Vote submitted successfully
 *       400:
 *         description: Invalid vote data
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Approval request not found
 *       409:
 *         description: Already voted or approval completed
 */
router.post('/approvals/:id/vote',
  requireRole(['admin', 'medical_director', 'financial_controller']),
  validate(Joi.object({
    vote: Joi.string().valid('approve', 'reject').required(),
    comment: Joi.string().max(1000).optional(),
  })),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { vote, comment = '' } = req.body;
    const userId = req.user!.id;
    const userRole = req.user!['role'];

    // Get approval request
    const approvalResult = await databaseService.query(
      'SELECT * FROM multisig_approvals WHERE id = $1',
      [id],
    );

    if (approvalResult.rows.length === 0) {
      throw new NotFoundError('Approval request');
    }

    const approval = approvalResult.rows[0];

    // Check if approval is still pending
    if (approval.status !== 'pending') {
      throw new BusinessLogicError('Approval request is no longer pending');
    }

    // Check if deadline has passed
    if (new Date() > new Date(approval.deadline)) {
      throw new BusinessLogicError('Approval deadline has passed');
    }

    // Check if user can vote on this approval
    const requiredApprovers = approval.required_approvers;
    if (!canUserApprove(userRole, requiredApprovers)) {
      throw new BusinessLogicError('You are not authorized to vote on this approval request');
    }

    // Check if user has already voted
    const existingVoteResult = await databaseService.query(
      'SELECT id FROM approval_votes WHERE approval_id = $1 AND voter_id = $2',
      [id, userId],
    );

    if (existingVoteResult.rows.length > 0) {
      throw new BusinessLogicError('You have already voted on this approval request');
    }

    const voteId = uuidv4();

    await databaseService.query('BEGIN');

    try {
      // Record the vote
      await databaseService.query(
        `INSERT INTO approval_votes (id, approval_id, voter_id, vote, comment)
         VALUES ($1, $2, $3, $4, $5)`,
        [voteId, id, userId, vote, comment],
      );

      // Get current vote counts
      const voteCountResult = await databaseService.query(
        `SELECT 
           COUNT(CASE WHEN vote = 'approve' THEN 1 END) as approve_count,
           COUNT(CASE WHEN vote = 'reject' THEN 1 END) as reject_count
         FROM approval_votes 
         WHERE approval_id = $1`,
        [id],
      );

      const { approve_count, reject_count } = voteCountResult.rows[0];
      const approveCount = parseInt(approve_count);
      const rejectCount = parseInt(reject_count);

      let newStatus = 'pending';
      let statusReason = '';

      // Check if approval threshold is met
      if (approveCount >= approval.approval_threshold) {
        newStatus = 'approved';
        statusReason = 'Approval threshold met';
      } else if (rejectCount > 0) {
        // Any rejection immediately rejects the approval
        newStatus = 'rejected';
        statusReason = 'Rejected by approver';
      }

      // Update approval status if changed
      if (newStatus !== 'pending') {
        await databaseService.query(
          'UPDATE multisig_approvals SET status = $1, resolved_at = NOW() WHERE id = $2',
          [newStatus, id],
        );

        // Update entity status
        if (newStatus === 'approved') {
          if (approval.entity_type === 'claim') {
            await databaseService.query(
              'UPDATE claims SET status = $1 WHERE id = $2',
              ['approved', approval.entity_id],
            );
          } else if (approval.entity_type === 'settlement') {
            await databaseService.query(
              'UPDATE settlements SET status = $1 WHERE id = $2',
              ['approved', approval.entity_id],
            );
          }
        } else if (newStatus === 'rejected') {
          if (approval.entity_type === 'claim') {
            await databaseService.query(
              'UPDATE claims SET status = $1, rejection_reason = $2 WHERE id = $3',
              ['rejected', statusReason, approval.entity_id],
            );
          } else if (approval.entity_type === 'settlement') {
            await databaseService.query(
              'UPDATE settlements SET status = $1 WHERE id = $2',
              ['cancelled', approval.entity_id],
            );
          }
        }

        // Submit to blockchain if approved
        if (newStatus === 'approved') {
          try {
            await blockchainService.submitApproval(id!, vote === 'approve', comment || '');
          } catch (blockchainError) {
            logger.warn('Failed to submit approval to blockchain', {
              approvalId: id,
              error: (blockchainError as Error).message,
            });
          }
        }
      }

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`approval:${id}`);
      await redisService.del(`approval_detail:${id}`);

      // Send notification to creator
      await databaseService.query(
        `INSERT INTO notifications (id, user_id, type, title, message, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          uuidv4(),
          approval.created_by,
          'approval_update',
          `Approval ${newStatus === 'pending' ? 'Vote Received' : newStatus.charAt(0).toUpperCase() + newStatus.slice(1)}`,
          `Your approval request has received a ${vote} vote${newStatus !== 'pending' ? ` and is now ${newStatus}` : ''}.`,
          JSON.stringify({ approvalId: id, vote, newStatus, entityType: approval.entity_type }),
        ],
      );

      logger.info('Approval vote submitted', {
        approvalId: id,
        vote,
        voterId: userId,
        voterRole: userRole,
        newStatus,
        approveCount,
        rejectCount,
        threshold: approval.approval_threshold,
      });

      res.json({
        message: 'Vote submitted successfully',
        vote: {
          id: voteId,
          vote,
          comment,
        },
        approval: {
          id,
          status: newStatus,
          approveCount,
          rejectCount,
          threshold: approval.approval_threshold,
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
 * /api/multisig/approvals/{id}/cancel:
 *   post:
 *     summary: Cancel a pending approval request
 *     tags: [Multi-Signature Approvals]
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
 *                 maxLength: 500
 *     responses:
 *       200:
 *         description: Approval request cancelled successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Approval request not found
 *       409:
 *         description: Cannot cancel completed approval
 */
router.post('/approvals/:id/cancel',
  requireRole(['admin']),
  validate(Joi.object({
    reason: Joi.string().max(1000).required(),
  })),
  asyncHandler(async (req: Request, res: Response): Promise<any> => {
    const { id } = req.params;
    const { reason } = req.body;
    const userId = req.user!.id;

    // Get approval request
    const approvalResult = await databaseService.query(
      'SELECT * FROM multisig_approvals WHERE id = $1',
      [id],
    );

    if (approvalResult.rows.length === 0) {
      throw new NotFoundError('Approval request');
    }

    const approval = approvalResult.rows[0];

    // Check if approval can be cancelled
    if (approval.status !== 'pending') {
      throw new BusinessLogicError('Only pending approval requests can be cancelled');
    }

    await databaseService.query('BEGIN');

    try {
      // Update approval status
      await databaseService.query(
        'UPDATE multisig_approvals SET status = $1, resolved_at = NOW(), metadata = $2 WHERE id = $3',
        ['cancelled', JSON.stringify({ ...approval.metadata, cancellationReason: reason, cancelledBy: userId }), id],
      );

      // Revert entity status
      if (approval.entity_type === 'claim') {
        await databaseService.query(
          'UPDATE claims SET status = $1 WHERE id = $2',
          ['under_review', approval.entity_id],
        );
      } else if (approval.entity_type === 'settlement') {
        await databaseService.query(
          'UPDATE settlements SET status = $1 WHERE id = $2',
          ['pending', approval.entity_id],
        );
      }

      await databaseService.query('COMMIT');

      // Clear cache
      await redisService.del(`approval:${id}`);
      await redisService.del(`approval_detail:${id}`);

      logger.info('Approval request cancelled', {
        approvalId: id,
        reason,
        cancelledBy: userId,
        entityType: approval.entity_type,
        entityId: approval.entity_id,
      });

      res.json({
        message: 'Approval request cancelled successfully',
        approval: {
          id,
          status: 'cancelled',
          reason,
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
 * /api/multisig/statistics:
 *   get:
 *     summary: Get multi-signature approval statistics
 *     tags: [Multi-Signature Approvals]
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
 *         description: Approval statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/statistics',
  requireRole(['admin', 'medical_director', 'financial_controller']),
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

    // Get overall statistics
    const statsQuery = `
      SELECT 
        COUNT(*) as total_approvals,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_count,
        COUNT(CASE WHEN status = 'expired' THEN 1 END) as expired_count,
        SUM(amount) as total_amount,
        AVG(amount) as avg_amount,
        AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) as avg_resolution_hours
      FROM multisig_approvals 
      WHERE created_at >= $1
    `;

    const statsResult = await databaseService.query(statsQuery, [startDate]);
    const stats = statsResult.rows[0];

    // Get statistics by entity type
    const entityStatsQuery = `
      SELECT 
        entity_type,
        COUNT(*) as count,
        SUM(amount) as total_amount,
        AVG(amount) as avg_amount
      FROM multisig_approvals 
      WHERE created_at >= $1
      GROUP BY entity_type
    `;

    const entityStatsResult = await databaseService.query(entityStatsQuery, [startDate]);
    const entityStats = entityStatsResult.rows.reduce((acc, row) => {
      acc[row.entity_type] = {
        count: parseInt(row.count),
        totalAmount: parseFloat(row.total_amount || 0),
        averageAmount: parseFloat(row.avg_amount || 0),
      };
      return acc;
    }, {});

    // Get statistics by urgency
    const urgencyStatsQuery = `
      SELECT 
        urgency,
        COUNT(*) as count,
        AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) as avg_resolution_hours
      FROM multisig_approvals 
      WHERE created_at >= $1 AND resolved_at IS NOT NULL
      GROUP BY urgency
    `;

    const urgencyStatsResult = await databaseService.query(urgencyStatsQuery, [startDate]);
    const urgencyStats = urgencyStatsResult.rows.reduce((acc, row) => {
      acc[row.urgency] = {
        count: parseInt(row.count),
        averageResolutionHours: parseFloat(row.avg_resolution_hours || 0),
      };
      return acc;
    }, {});

    // Get daily trend
    const trendQuery = `
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as created_count,
        COUNT(CASE WHEN resolved_at IS NOT NULL AND DATE(resolved_at) = DATE(created_at) THEN 1 END) as resolved_same_day
      FROM multisig_approvals 
      WHERE created_at >= $1
      GROUP BY DATE(created_at)
      ORDER BY date
    `;

    const trendResult = await databaseService.query(trendQuery, [startDate]);
    const trends = trendResult.rows.map(row => ({
      date: row.date,
      createdCount: parseInt(row.created_count),
      resolvedSameDay: parseInt(row.resolved_same_day),
    }));

    res.json({
      period,
      dateRange: {
        from: startDate,
        to: now,
      },
      statistics: {
        totalApprovals: parseInt(stats.total_approvals),
        pendingCount: parseInt(stats.pending_count),
        approvedCount: parseInt(stats.approved_count),
        rejectedCount: parseInt(stats.rejected_count),
        expiredCount: parseInt(stats.expired_count),
        totalAmount: parseFloat(stats.total_amount || 0),
        averageAmount: parseFloat(stats.avg_amount || 0),
        averageResolutionHours: parseFloat(stats.avg_resolution_hours || 0),
        approvalRate: stats.total_approvals > 0 ?
          ((stats.approved_count / stats.total_approvals) * 100).toFixed(2) : 0,
      },
      entityStats,
      urgencyStats,
      trends,
    });
  }),
);

export default router;