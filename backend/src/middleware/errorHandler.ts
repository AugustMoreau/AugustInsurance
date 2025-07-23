import type { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';
import { config } from '../config';

// Custom error classes
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public errorCode?: string | undefined;
  public details?: any;

  constructor(
    message: string,
    statusCode: number = 500,
    errorCode?: string,
    details?: any,
    isOperational: boolean = true,
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.errorCode = errorCode;
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND_ERROR');
  }
}

export class ConflictError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 409, 'CONFLICT_ERROR', details);
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_ERROR');
  }
}

export class BlockchainError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 500, 'BLOCKCHAIN_ERROR', details);
  }
}

export class DatabaseError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 500, 'DATABASE_ERROR', details);
  }
}

export class ExternalServiceError extends AppError {
  constructor(service: string, message: string, details?: any) {
    super(`${service} service error: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR', details);
  }
}

export class BusinessLogicError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 422, 'BUSINESS_LOGIC_ERROR', details);
  }
}

// Error response interface
interface ErrorResponse {
  error: string;
  message: string;
  statusCode: number;
  errorCode?: string | undefined;
  details?: any;
  timestamp: string;
  path: string;
  requestId?: string | undefined;
  stack?: string;
}

// Error categorization
const getErrorCategory = (error: Error): string => {
  if (error instanceof ValidationError) {
    return 'validation';
  }
  if (error instanceof AuthenticationError) {
    return 'authentication';
  }
  if (error instanceof AuthorizationError) {
    return 'authorization';
  }
  if (error instanceof NotFoundError) {
    return 'not_found';
  }
  if (error instanceof ConflictError) {
    return 'conflict';
  }
  if (error instanceof RateLimitError) {
    return 'rate_limit';
  }
  if (error instanceof BlockchainError) {
    return 'blockchain';
  }
  if (error instanceof DatabaseError) {
    return 'database';
  }
  if (error instanceof ExternalServiceError) {
    return 'external_service';
  }
  if (error instanceof BusinessLogicError) {
    return 'business_logic';
  }
  return 'unknown';
};

// Error severity levels
const getErrorSeverity = (statusCode: number): 'low' | 'medium' | 'high' | 'critical' => {
  if (statusCode >= 500) {
    return 'critical';
  }
  if (statusCode >= 400) {
    return 'medium';
  }
  return 'low';
};

// Handle specific error types
const handleCastError = (error: any): AppError => {
  const message = `Invalid ${error.path}: ${error.value}`;
  return new ValidationError(message);
};

const handleDuplicateFieldsError = (error: any): AppError => {
  const value = error.errmsg?.match(/(["'])((?:(?!\1)[^\\]|\\.)*)\1/)?.[2];
  const message = `Duplicate field value: ${value}. Please use another value`;
  return new ConflictError(message);
};

const handleValidationError = (error: any): AppError => {
  const errors = Object.values(error.errors).map((val: any) => val.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new ValidationError(message, errors);
};

const handleJWTError = (): AppError => {
  return new AuthenticationError('Invalid token. Please log in again');
};

const handleJWTExpiredError = (): AppError => {
  return new AuthenticationError('Your token has expired. Please log in again');
};

const handlePostgresError = (error: any): AppError => {
  const { code, detail, constraint } = error;

  switch (code) {
    case '23505': // Unique violation
      return new ConflictError('Duplicate entry', { constraint, detail });
    case '23503': // Foreign key violation
      return new ValidationError('Referenced record does not exist', { constraint, detail });
    case '23502': // Not null violation
      return new ValidationError('Required field is missing', { constraint, detail });
    case '23514': // Check violation
      return new ValidationError('Data validation failed', { constraint, detail });
    case '42P01': // Undefined table
      return new DatabaseError('Database table not found', { detail });
    case '42703': // Undefined column
      return new DatabaseError('Database column not found', { detail });
    default:
      return new DatabaseError('Database operation failed', { code, detail });
  }
};

// Main error handling middleware
export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  let error = { ...err } as AppError;
  error.message = err.message;

  // Log the original error
  logger.logError(err, 'Error Handler', {
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    sessionId: req.sessionId,
    body: req.method !== 'GET' ? req.body : undefined,
    query: req.query,
    params: req.params,
  });

  // Handle specific error types
  if (err.name === 'CastError') {
    error = handleCastError(err);
  } else if (err.name === 'ValidationError') {
    error = handleValidationError(err);
  } else if (err.name === 'JsonWebTokenError') {
    error = handleJWTError();
  } else if (err.name === 'TokenExpiredError') {
    error = handleJWTExpiredError();
  } else if ((err as any).code?.startsWith('23')) {
    error = handlePostgresError(err);
  } else if (err.message?.includes('duplicate key')) {
    error = handleDuplicateFieldsError(err);
  } else if (!(err instanceof AppError)) {
    // Handle unknown errors
    error = new AppError(
      config.env === 'production' ? 'Something went wrong' : err.message,
      500,
      'INTERNAL_SERVER_ERROR',
      config.env === 'production' ? undefined : err.stack,
    );
  }

  // Prepare error response
  const errorResponse: ErrorResponse = {
    error: error.constructor.name,
    message: error.message,
    statusCode: error.statusCode || 500,
    errorCode: error.errorCode || undefined,
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    requestId: (req.headers['x-request-id'] as string) || undefined,
  };

  // Include details in non-production environments or for operational errors
  if (config.env !== 'production' || error.isOperational) {
    if (error.details) {
      errorResponse.details = error.details;
    }
  }

  // Include stack trace in development
  if (config.env === 'development') {
    errorResponse.stack = error.stack || '';
  }

  // Log error metrics
  const category = getErrorCategory(error);
  const severity = getErrorSeverity(error.statusCode || 500);

  logger.info('Error metrics', {
    category,
    severity,
    statusCode: error.statusCode,
    errorCode: error.errorCode,
    endpoint: req.originalUrl,
    method: req.method,
    userId: req.user?.id,
    duration: Date.now() - (req as any).startTime,
  });

  // Send error response
  res.status(error.statusCode || 500).json(errorResponse);
};

// 404 handler for undefined routes
export const notFoundHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const error = new NotFoundError(`Route ${req.originalUrl}`);
  next(error);
};

// Async error wrapper
export const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>,
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Global unhandled rejection handler
export const handleUnhandledRejection = (): void => {
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise.toString(),
    });

    // Graceful shutdown
    process.exit(1);
  });
};

// Global uncaught exception handler
export const handleUncaughtException = (): void => {
  process.on('uncaughtException', (error: Error) => {
    logger.error('Uncaught Exception', {
      message: error.message,
      stack: error.stack,
      name: error.name,
    });

    // Graceful shutdown
    process.exit(1);
  });
};

// Graceful shutdown handler
export const handleGracefulShutdown = (): void => {
  const gracefulShutdown = (signal: string) => {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);

    // Close server and cleanup resources
    process.exit(0);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
};

// Error monitoring and alerting
export const monitorErrors = (): ((err: Error, req: Request, res: Response, next: NextFunction) => void) => {
  const errorCounts: Record<string, number> = {};
  const errorThreshold = 10; // Alert after 10 errors of same type in 5 minutes
  const timeWindow = 5 * 60 * 1000; // 5 minutes

  setInterval(() => {
    Object.keys(errorCounts).forEach(errorType => {
      if ((errorCounts[errorType] || 0) >= errorThreshold) {
        logger.error('High error rate detected', {
          errorType,
          count: errorCounts[errorType],
          timeWindow: timeWindow / 1000,
        });

        // Here you could integrate with alerting services like PagerDuty, Slack, etc.
      }

      // Reset counter
      errorCounts[errorType] = 0;
    });
  }, timeWindow);

  // Track errors
  const originalErrorHandler = errorHandler;
  const trackingHandler = (err: Error, req: Request, res: Response, next: NextFunction): void => {
    const errorType = err.constructor.name;
    errorCounts[errorType] = (errorCounts[errorType] || 0) + 1;

    originalErrorHandler(err, req, res, next);
  };

  return trackingHandler;
};

// Health check error handler
export const healthCheckErrorHandler = (
  error: Error,
  service: string,
): { status: 'unhealthy'; error: string; timestamp: string } => {
  logger.logError(error, `Health check failed for ${service}`, { service });

  return {
    status: 'unhealthy',
    error: error.message,
    timestamp: new Date().toISOString(),
  };
};

// Request timeout handler
export const timeoutHandler = (timeout: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const timer = setTimeout(() => {
      const error = new AppError(
        'Request timeout',
        408,
        'REQUEST_TIMEOUT',
        { timeout: timeout / 1000 },
      );
      next(error);
    }, timeout);

    // Clear timeout if request completes
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));

    next();
  };
};

// Circuit breaker for external services
export class CircuitBreaker {
  private failures: number = 0;
  private lastFailureTime: number = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  constructor(
    private threshold: number = 5,
    private timeout: number = 60000,
    private monitoringPeriod: number = 10000,
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'half-open';
      } else {
        throw new ExternalServiceError('Circuit Breaker', 'Service temporarily unavailable');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.threshold) {
      this.state = 'open';
      logger.warn('Circuit breaker opened', {
        failures: this.failures,
        threshold: this.threshold,
      });
    }
  }

  getState(): { state: string; failures: number; lastFailureTime: number } {
    return {
      state: this.state,
      failures: this.failures,
      lastFailureTime: this.lastFailureTime,
    };
  }
}