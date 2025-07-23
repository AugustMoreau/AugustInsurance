import type { Request, Response } from 'express';
import { Router } from 'express';
import bcrypt from 'bcryptjs'; // for password hashing
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import logger from '../utils/logger'; // winston logger
import databaseService from '../services/DatabaseService';
import redisService from '../services/RedisService';
import { validate, userSchemas } from '../middleware/validation';
import { authMiddleware, requirePermission, PERMISSIONS } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import {
  AppError,
  ValidationError,
  AuthenticationError,
  ConflictError,
  NotFoundError,
} from '../middleware/errorHandler';

const router = Router();

// Rate limiting for auth endpoints - might be too strict?
const authRateLimit = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window - users will complain about this
  skipSuccessfulRequests: true,
};

// Helper function to generate JWT token
const generateToken = (payload: any): string => {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  } as any); // TODO: fix this any type
};

// Hash passwords with bcrypt - 12 rounds should be enough
const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12; // might increase this later
  return bcrypt.hash(password, saltRounds);
};

// Helper function to verify password
const verifyPassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

// Helper function to create user session
const createUserSession = async (userId: string, req: Request): Promise<string> => {
  const sessionId = uuidv4();
  const sessionData: any = {
    userId,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ipAddress: req.ip,
    userAgent: req.get('User-Agent') || 'Unknown',
    isActive: true,
  };

  await redisService.createSession(sessionId, sessionData);
  return sessionId;
};

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - firstName
 *               - lastName
 *               - phone
 *               - dateOfBirth
 *               - address
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [admin, claims_processor, medical_director, financial_controller, fraud_analyst, provider, patient, auditor]
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *               address:
 *                 type: object
 *                 properties:
 *                   street:
 *                     type: string
 *                   city:
 *                     type: string
 *                   state:
 *                     type: string
 *                   zipCode:
 *                     type: string
 *                   country:
 *                     type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 *       409:
 *         description: User already exists
 */
router.post('/register',
  validate(userSchemas.register),
  asyncHandler(async (req: Request, res: Response) => {
    const {
      email,
      password,
      firstName,
      lastName,
      phone,
      role = 'patient',
      dateOfBirth,
      address,
    } = req.body;

    // Check if user already exists
    const existingUser = await databaseService.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()],
    );

    if (existingUser.rows.length > 0) {
      throw new ConflictError('User with this email already exists');
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const userResult = await databaseService.query(
      `INSERT INTO users (
        email, password_hash, first_name, last_name, phone, role,
        date_of_birth, address, is_active, email_verified
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, email, first_name, last_name, role, created_at`,
      [
        email.toLowerCase(),
        hashedPassword,
        firstName,
        lastName,
        phone,
        role,
        dateOfBirth,
        JSON.stringify(address),
        true, // is_active
        false, // email_verified
      ],
    );

    const user = userResult.rows[0];

    // Create session
    const sessionId = await createUserSession(user.id, req);

    // Generate JWT token
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    });

    // Log successful registration
    logger.info('User registered successfully', {
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        createdAt: user.created_at,
      },
      token,
      sessionId,
    });
  }),
);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               rememberMe:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
router.post('/login',
  validate(userSchemas.login),
  asyncHandler(async (req: Request, res: Response) => {
    const { email, password, rememberMe = false } = req.body;

    // Find user
    const userResult = await databaseService.query(
      `SELECT id, email, password_hash, first_name, last_name, role, 
              is_active, email_verified, last_login, failed_login_attempts,
              locked_until
       FROM users WHERE email = $1`,
      [email.toLowerCase()],
    );

    if (userResult.rows.length === 0) {
      logger.logSecurityEvent('Login attempt with non-existent email', 'medium', {
        email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });
      throw new AuthenticationError('Invalid email or password');
    }

    const user = userResult.rows[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logger.logSecurityEvent('Login attempt on locked account', 'high', {
        userId: user.id,
        email: user.email,
        lockedUntil: user.locked_until,
        ip: req.ip,
      });
      throw new AuthenticationError('Account is temporarily locked due to multiple failed login attempts');
    }

    // Check if account is active
    if (!user.is_active) {
      logger.logSecurityEvent('Login attempt on inactive account', 'medium', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
      });
      throw new AuthenticationError('Account is disabled. Please contact support');
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password_hash);

    if (!isPasswordValid) {
      // Increment failed login attempts
      const failedAttempts = (user.failed_login_attempts || 0) + 1;
      const maxAttempts = 5;
      const lockDuration = 30 * 60 * 1000; // 30 minutes

      let updateQuery = 'UPDATE users SET failed_login_attempts = $1';
      const updateParams = [failedAttempts];

      if (failedAttempts >= maxAttempts) {
        const lockedUntil = new Date(Date.now() + lockDuration);
        updateQuery += ', locked_until = $2';
        updateParams.push(lockedUntil.toISOString());
      }

      updateQuery += ` WHERE id = $${updateParams.length + 1}`;
      updateParams.push(user.id);

      await databaseService.query(updateQuery, updateParams);

      logger.logSecurityEvent('Failed login attempt', 'medium', {
        userId: user.id,
        email: user.email,
        failedAttempts,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      throw new AuthenticationError('Invalid email or password');
    }

    // Reset failed login attempts on successful login
    await databaseService.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id],
    );

    // Create session
    const sessionId = await createUserSession(user.id, req);

    // Generate JWT token
    const tokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    };

    const tokenOptions = rememberMe ? { expiresIn: '30d' } : { expiresIn: config.jwt.expiresIn };
    const token = jwt.sign(tokenPayload, config.jwt.secret, tokenOptions as any);

    // Log successful login
    logger.info('User logged in successfully', {
      userId: user.id,
      email: user.email,
      role: user.role,
      rememberMe,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        lastLogin: user.last_login,
        emailVerified: user.email_verified,
      },
      token,
      sessionId,
    });
  }),
);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *       401:
 *         description: Authentication required
 */
router.post('/logout',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const { sessionId } = req;

    if (sessionId) {
      await redisService.deleteSession(sessionId);
    }

    logger.info('User logged out', {
      userId: req.user?.id,
      sessionId,
      ip: req.ip,
    });

    res.json({ message: 'Logout successful' });
  }),
);

/**
 * @swagger
 * /api/auth/logout-all:
 *   post:
 *     summary: Logout from all devices
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all devices
 *       401:
 *         description: Authentication required
 */
router.post('/logout-all',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;

    await redisService.deleteUserSessions(userId);

    logger.info('User logged out from all devices', {
      userId,
      ip: req.ip,
    });

    res.json({ message: 'Logged out from all devices successfully' });
  }),
);

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh authentication token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Authentication required
 */
router.post('/refresh',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const sessionId = req.sessionId!;

    // Generate new token
    const token = generateToken({
      userId: user.id,
      email: user['email'],
      role: user['role'],
      sessionId,
    });

    // Update session activity
    await redisService.updateSession(sessionId, {
      lastActivity: Date.now(),
    });

    logger.debug('Token refreshed', {
      userId: user.id,
      sessionId,
      ip: req.ip,
    });

    res.json({
      message: 'Token refreshed successfully',
      token,
    });
  }),
);

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Get user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/profile',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;

    const userResult = await databaseService.query(
      `SELECT id, email, first_name, last_name, phone, role, date_of_birth,
              address, is_active, email_verified, created_at, updated_at, last_login
       FROM users WHERE id = $1`,
      [userId],
    );

    if (userResult.rows.length === 0) {
      throw new NotFoundError('User');
    }

    const user = userResult.rows[0];

    res.json({
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        phone: user.phone,
        role: user.role,
        dateOfBirth: user.date_of_birth,
        address: user.address,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        lastLogin: user.last_login,
      },
    });
  }),
);

/**
 * @swagger
 * /api/auth/profile:
 *   put:
 *     summary: Update user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: object
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       401:
 *         description: Authentication required
 */
router.put('/profile',
  authMiddleware,
  validate(userSchemas.updateProfile),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { firstName, lastName, phone, address } = req.body;

    const updateFields: string[] = [];
    const updateValues: any[] = [];
    let paramIndex = 1;

    if (firstName) {
      updateFields.push(`first_name = $${paramIndex++}`);
      updateValues.push(firstName);
    }

    if (lastName) {
      updateFields.push(`last_name = $${paramIndex++}`);
      updateValues.push(lastName);
    }

    if (phone) {
      updateFields.push(`phone = $${paramIndex++}`);
      updateValues.push(phone);
    }

    if (address) {
      updateFields.push(`address = $${paramIndex++}`);
      updateValues.push(JSON.stringify(address));
    }

    if (updateFields.length === 0) {
      throw new ValidationError('No fields to update');
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(userId);

    const query = `
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING id, email, first_name, last_name, phone, address, updated_at
    `;

    const result = await databaseService.query(query, updateValues);
    const updatedUser = result.rows[0];

    logger.info('User profile updated', {
      userId,
      updatedFields: Object.keys(req.body),
      ip: req.ip,
    });

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        firstName: updatedUser.first_name,
        lastName: updatedUser.last_name,
        phone: updatedUser.phone,
        address: updatedUser.address,
        updatedAt: updatedUser.updated_at,
      },
    });
  }),
);

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       401:
 *         description: Authentication required or invalid current password
 */
router.post('/change-password',
  authMiddleware,
  validate(userSchemas.changePassword),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { currentPassword, newPassword } = req.body;

    // Get current password hash
    const userResult = await databaseService.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId],
    );

    if (userResult.rows.length === 0) {
      throw new NotFoundError('User');
    }

    const { password_hash } = userResult.rows[0];

    // Verify current password
    const isCurrentPasswordValid = await verifyPassword(currentPassword, password_hash);

    if (!isCurrentPasswordValid) {
      logger.logSecurityEvent('Invalid current password in change password attempt', 'medium', {
        userId,
        ip: req.ip,
      });
      throw new AuthenticationError('Current password is incorrect');
    }

    // Hash new password
    const newPasswordHash = await hashPassword(newPassword);

    // Update password
    await databaseService.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [newPasswordHash, userId],
    );

    // Invalidate all user sessions except current one
    const currentSessionId = req.sessionId!;
    const userSessions = await redisService.getUserSessions(userId);

    for (const sessionId of userSessions) {
      if (sessionId !== currentSessionId) {
        await redisService.deleteSession(sessionId);
      }
    }

    logger.info('Password changed successfully', {
      userId,
      ip: req.ip,
      sessionsInvalidated: userSessions.length - 1,
    });

    res.json({
      message: 'Password changed successfully. Other sessions have been logged out.',
    });
  }),
);

/**
 * @swagger
 * /api/auth/sessions:
 *   get:
 *     summary: Get active sessions
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Active sessions retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/sessions',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const currentSessionId = req.sessionId!;

    const sessionIds = await redisService.getUserSessions(userId);
    const sessions = [];

    for (const sessionId of sessionIds) {
      const sessionData = await redisService.getSession(sessionId);
      if (sessionData) {
        sessions.push({
          sessionId,
          createdAt: sessionData.createdAt ? new Date(sessionData.createdAt).toISOString() : new Date().toISOString(),
          lastActivity: new Date(sessionData.lastActivity).toISOString(),
          ipAddress: sessionData.ipAddress,
          userAgent: sessionData.userAgent,
          isCurrent: sessionId === currentSessionId,
        });
      }
    }

    res.json({ sessions });
  }),
);

/**
 * @swagger
 * /api/auth/sessions/{sessionId}:
 *   delete:
 *     summary: Terminate a specific session
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session terminated successfully
 *       401:
 *         description: Authentication required
 *       404:
 *         description: Session not found
 */
router.delete('/sessions/:sessionId',
  authMiddleware,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { sessionId } = req.params;

    const sessionData = await redisService.getSession(sessionId!);

    if (!sessionData || sessionData.userId !== userId) {
      throw new NotFoundError('Session');
    }

    await redisService.deleteSession(sessionId!);

    logger.info('Session terminated', {
      userId,
      terminatedSessionId: sessionId,
      ip: req.ip,
    });

    res.json({ message: 'Session terminated successfully' });
  }),
);

export default router;