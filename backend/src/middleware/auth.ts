import type { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { config } from '../config';
import logger from '../utils/logger';
import databaseService from '../services/DatabaseService';
import type { SessionData } from '../services/RedisService';
import redisService from '../services/RedisService';

// Auth middleware - this took way too long to get right

interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  sessionId: string;
  iat: number;
  exp: number;
}

interface AuthenticatedUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  permissions: string[];
  sessionId: string;
}

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      sessionId?: string;
    }
  }
}

// Role-based permissions - probably should move this to a config file
const ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: [
    'claims:read', 'claims:write', 'claims:approve', 'claims:reject', 'claims:settle',
    'providers:read', 'providers:write', 'providers:approve', 'providers:suspend',
    'policies:read', 'policies:write', 'policies:activate', 'policies:deactivate',
    'settlements:read', 'settlements:write', 'settlements:process',
    'fraud:read', 'fraud:write', 'fraud:investigate',
    'analytics:read', 'analytics:export',
    'users:read', 'users:write', 'users:activate', 'users:deactivate',
    'system:read', 'system:write', 'system:configure', // admin can do everything
  ],
  claims_processor: [
    'claims:read', 'claims:write', 'claims:review',
    'providers:read',
    'policies:read',
    'settlements:read',
    'fraud:read',
    'analytics:read',
  ],
  medical_director: [
    'claims:read', 'claims:approve', 'claims:reject',
    'providers:read', 'providers:approve',
    'policies:read',
    'settlements:read',
    'fraud:read', 'fraud:investigate',
    'analytics:read',
  ],
  financial_controller: [
    'claims:read', 'claims:approve', 'claims:reject', 'claims:settle',
    'providers:read',
    'policies:read',
    'settlements:read', 'settlements:write', 'settlements:process',
    'fraud:read',
    'analytics:read', 'analytics:export',
  ],
  fraud_analyst: [
    'claims:read',
    'providers:read',
    'policies:read',
    'settlements:read',
    'fraud:read', 'fraud:write', 'fraud:investigate',
    'analytics:read',
  ],
  provider: [
    'claims:read', 'claims:write',
    'settlements:read',
    'analytics:read',
  ],
  patient: [
    'claims:read',
    'policies:read',
    'settlements:read',
  ],
  auditor: [
    'claims:read',
    'providers:read',
    'policies:read',
    'settlements:read',
    'fraud:read',
    'analytics:read', 'analytics:export',
  ],
};

// Authentication middleware
export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'Please provide a valid authentication token',
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify JWT token
    let payload: JWTPayload;
    try {
      payload = jwt.verify(token, config.jwt.secret) as JWTPayload;
    } catch (jwtError) {
      logger.logSecurityEvent('Invalid JWT token', 'medium', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        token: `${token.substring(0, 20)}...`,
      });

      res.status(401).json({
        error: 'Invalid token',
        message: 'The provided authentication token is invalid or expired',
      });
      return;
    }

    // Check if session exists in Redis
    const sessionData = await redisService.getSession(payload.sessionId);
    if (!sessionData) {
      logger.logSecurityEvent('Session not found', 'medium', {
        userId: payload.userId,
        sessionId: payload.sessionId,
        ip: req.ip,
      });

      res.status(401).json({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again',
      });
      return;
    }

    // Verify session belongs to the same user
    if (sessionData.userId !== payload.userId) {
      logger.logSecurityEvent('Session user mismatch', 'high', {
        tokenUserId: payload.userId,
        sessionUserId: sessionData.userId,
        sessionId: payload.sessionId,
        ip: req.ip,
      });

      res.status(401).json({
        error: 'Invalid session',
        message: 'Session validation failed',
      });
      return;
    }

    // Check if user is still active in database
    const userResult = await databaseService.query(
      'SELECT id, email, first_name, last_name, role, is_active FROM users WHERE id = $1',
      [payload.userId],
    );

    if (userResult.rows.length === 0) {
      logger.logSecurityEvent('User not found', 'high', {
        userId: payload.userId,
        ip: req.ip,
      });

      res.status(401).json({
        error: 'User not found',
        message: 'User account not found',
      });
      return;
    }

    const user = userResult.rows[0];
    if (!user.is_active) {
      logger.logSecurityEvent('Inactive user access attempt', 'medium', {
        userId: payload.userId,
        email: user.email,
        ip: req.ip,
      });

      res.status(401).json({
        error: 'Account disabled',
        message: 'Your account has been disabled. Please contact support',
      });
      return;
    }

    // Check for role changes
    if (user.role !== payload.role) {
      logger.logSecurityEvent('User role changed', 'medium', {
        userId: payload.userId,
        oldRole: payload.role,
        newRole: user.role,
        ip: req.ip,
      });

      // Invalidate all user sessions due to role change
      await redisService.deleteUserSessions(payload.userId);

      res.status(401).json({
        error: 'Role changed',
        message: 'Your role has been updated. Please log in again',
      });
      return;
    }

    // Update session activity
    const sessionUpdate: Partial<SessionData> = {
      lastActivity: Date.now(),
    };

    if (req.ip) {
      sessionUpdate.ipAddress = req.ip;
    }

    const userAgent = req.get('User-Agent');
    if (userAgent) {
      sessionUpdate.userAgent = userAgent;
    }

    await redisService.updateSession(payload.sessionId, sessionUpdate);

    // Get user permissions
    const permissions = ROLE_PERMISSIONS[user.role] || [];

    // Attach user information to request
    req.user = {
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      permissions,
      sessionId: payload.sessionId,
    };

    req.sessionId = payload.sessionId;

    // Log successful authentication
    logger.debug('User authenticated successfully', {
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: req.ip,
      endpoint: req.originalUrl,
    });

    next();
  } catch (error) {
    logger.logError(error as Error, 'Authentication middleware', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
    });

    res.status(500).json({
      error: 'Authentication error',
      message: 'An error occurred during authentication',
    });
  }
};

// Authorization middleware factory
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'Please authenticate first',
      });
      return;
    }

    if (!req.user['permissions'].includes(permission)) {
      logger.logSecurityEvent('Insufficient permissions', 'medium', {
        userId: req.user.id,
        role: req.user['role'],
        requiredPermission: permission,
        userPermissions: req.user['permissions'],
        ip: req.ip,
        endpoint: req.originalUrl,
      });

      res.status(403).json({
        error: 'Insufficient permissions',
        message: `You don't have permission to perform this action. Required: ${permission}`,
      });
      return;
    }

    next();
  };
};

// Role-based authorization middleware
export const requireRole = (roles: string | string[]) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'Please authenticate first',
      });
      return;
    }

    if (!allowedRoles.includes(req.user['role'])) {
      logger.logSecurityEvent('Insufficient role', 'medium', {
        userId: req.user.id,
        userRole: req.user['role'],
        requiredRoles: allowedRoles,
        ip: req.ip,
        endpoint: req.originalUrl,
      });

      res.status(403).json({
        error: 'Insufficient role',
        message: `Access denied. Required roles: ${allowedRoles.join(', ')}`,
      });
      return;
    }

    next();
  };
};

// Resource ownership middleware
export const requireOwnership = (resourceIdParam: string = 'id') => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'Please authenticate first',
      });
      return;
    }

    // Admins can access any resource
    if (req.user['role'] === 'admin') {
      next();
      return;
    }

    const resourceId = req.params[resourceIdParam];
    if (!resourceId) {
      res.status(400).json({
        error: 'Invalid request',
        message: 'Resource ID is required',
      });
      return;
    }

    try {
      // Check ownership based on the endpoint
      const endpoint = req.route?.path || req.originalUrl;
      let ownershipQuery = '';
      let queryParams: any[] = [];

      if (endpoint.includes('/claims')) {
        // For claims, check if user is the patient or provider
        ownershipQuery = `
          SELECT c.id FROM claims c 
          WHERE c.id = $1 AND (c.patient_id = $2 OR c.provider_id IN (
            SELECT p.id FROM providers p WHERE p.id = $2
          ))
        `;
        queryParams = [resourceId, req.user.id];
      } else if (endpoint.includes('/policies')) {
        // For policies, check if user is the holder
        ownershipQuery = 'SELECT id FROM policies WHERE id = $1 AND holder_id = $2';
        queryParams = [resourceId, req.user.id];
      } else if (endpoint.includes('/settlements')) {
        // For settlements, check if user is the provider
        ownershipQuery = `
          SELECT s.id FROM settlements s 
          JOIN providers p ON s.provider_id = p.id 
          WHERE s.id = $1 AND p.id = $2
        `;
        queryParams = [resourceId, req.user.id];
      } else {
        // Default: check if resource belongs to user
        ownershipQuery = 'SELECT id FROM users WHERE id = $1 AND id = $2';
        queryParams = [resourceId, req.user.id];
      }

      const result = await databaseService.query(ownershipQuery, queryParams);

      if (result.rows.length === 0) {
        logger.logSecurityEvent('Unauthorized resource access', 'medium', {
          userId: req.user.id,
          resourceId,
          endpoint,
          ip: req.ip,
        });

        res.status(403).json({
          error: 'Access denied',
          message: 'You can only access your own resources',
        });
        return;
      }

      next();
    } catch (error) {
      logger.logError(error as Error, 'Ownership check', {
        userId: req.user.id,
        resourceId,
        endpoint: req.originalUrl,
      });

      res.status(500).json({
        error: 'Authorization error',
        message: 'An error occurred during authorization',
      });
    }
  };
};

// Rate limiting by user
export const userRateLimit = (maxRequests: number = 100, windowMs: number = 15 * 60 * 1000) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      next();
      return;
    }

    const key = `rate_limit:${req.user.id}`;
    const current = await redisService.get<number>(key) || 0;

    if (current >= maxRequests) {
      logger.logSecurityEvent('Rate limit exceeded', 'medium', {
        userId: req.user.id,
        requests: current,
        limit: maxRequests,
        ip: req.ip,
      });

      res.status(429).json({
        error: 'Rate limit exceeded',
        message: `Too many requests. Limit: ${maxRequests} per ${windowMs / 1000} seconds`,
        retryAfter: Math.ceil(windowMs / 1000),
      });
      return;
    }

    // Increment counter
    await redisService.set(key, current + 1, { ttl: Math.ceil(windowMs / 1000) });

    next();
  };
};

// Session validation middleware
export const validateSession = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.user || !req.sessionId) {
    next();
    return;
  }

  try {
    const sessionData = await redisService.getSession(req.sessionId);

    if (!sessionData) {
      res.status(401).json({
        error: 'Session expired',
        message: 'Your session has expired. Please log in again',
      });
      return;
    }

    // Check for concurrent sessions limit
    const userSessions = await redisService.getUserSessions(req.user.id);
    const maxSessions = config.constants.maxConcurrentSessions;

    if (userSessions.length > maxSessions) {
      logger.logSecurityEvent('Too many concurrent sessions', 'medium', {
        userId: req.user.id,
        sessionCount: userSessions.length,
        maxSessions,
        ip: req.ip,
      });

      // Remove oldest sessions
      const sessionsToRemove = userSessions.slice(0, userSessions.length - maxSessions);
      for (const sessionId of sessionsToRemove) {
        await redisService.deleteSession(sessionId);
      }
    }

    // Check session timeout
    const sessionTimeout = config.constants.sessionTimeoutMinutes * 60 * 1000;
    const lastActivity = sessionData.lastActivity || Date.now();

    if (Date.now() - lastActivity > sessionTimeout) {
      await redisService.deleteSession(req.sessionId);

      res.status(401).json({
        error: 'Session timeout',
        message: 'Your session has timed out due to inactivity',
      });
      return;
    }

    next();
  } catch (error) {
    logger.logError(error as Error, 'Session validation', {
      userId: req.user.id,
      sessionId: req.sessionId,
    });

    res.status(500).json({
      error: 'Session validation error',
      message: 'An error occurred during session validation',
    });
  }
};

// Export permission constants for use in routes
export const PERMISSIONS = {
  CLAIMS: {
    READ: 'claims:read',
    WRITE: 'claims:write',
    APPROVE: 'claims:approve',
    REJECT: 'claims:reject',
    SETTLE: 'claims:settle',
    REVIEW: 'claims:review',
  },
  PROVIDERS: {
    READ: 'providers:read',
    WRITE: 'providers:write',
    APPROVE: 'providers:approve',
    SUSPEND: 'providers:suspend',
  },
  POLICIES: {
    READ: 'policies:read',
    WRITE: 'policies:write',
    ACTIVATE: 'policies:activate',
    DEACTIVATE: 'policies:deactivate',
  },
  SETTLEMENTS: {
    READ: 'settlements:read',
    WRITE: 'settlements:write',
    PROCESS: 'settlements:process',
  },
  FRAUD: {
    READ: 'fraud:read',
    WRITE: 'fraud:write',
    INVESTIGATE: 'fraud:investigate',
  },
  ANALYTICS: {
    READ: 'analytics:read',
    EXPORT: 'analytics:export',
  },
  USERS: {
    READ: 'users:read',
    WRITE: 'users:write',
    ACTIVATE: 'users:activate',
    DEACTIVATE: 'users:deactivate',
  },
  SYSTEM: {
    READ: 'system:read',
    WRITE: 'system:write',
    CONFIGURE: 'system:configure',
  },
};

export { AuthenticatedUser, ROLE_PERMISSIONS };