import * as winston from 'winston';
import DailyRotateFile = require('winston-daily-rotate-file');
import { config } from '../config';

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// Tell winston that you want to link the colors
winston.addColors(colors);

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => {
      const { timestamp, level, message, stack, ...meta } = info;

      let log = `${timestamp} [${level}]: ${message}`;

      // Add stack trace for errors
      if (stack) {
        log += `\n${stack}`;
      }

      // Add metadata if present
      if (Object.keys(meta).length > 0) {
        log += `\n${JSON.stringify(meta, null, 2)}`;
      }

      return log;
    },
  ),
);

// Define log format for files (without colors)
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

// Define which transports the logger must use
const transports: winston.transport[] = [];

// Console transport
if (config.env !== 'production') {
  transports.push(
    new winston.transports.Console({
      format,
      level: config.monitoring.logLevel,
    }),
  );
}

// File transports for production
if (config.env === 'production') {
  // Error log file
  transports.push(
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      format: fileFormat,
      maxSize: '20m',
      maxFiles: '14d',
      zippedArchive: true,
    }),
  );

  // Combined log file
  transports.push(
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      format: fileFormat,
      maxSize: '20m',
      maxFiles: '14d',
      zippedArchive: true,
      level: config.monitoring.logLevel,
    }),
  );

  // Console transport for production (minimal)
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.simple(),
      ),
      level: 'error',
    }),
  );
}

// Create the logger
const logger = winston.createLogger({
  level: config.monitoring.logLevel,
  levels,
  format: fileFormat,
  transports,
  exitOnError: false,
});

// Create a stream object for Morgan HTTP logging
const stream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

// Enhanced logging methods with context
class Logger {
  private winston: winston.Logger;

  constructor(winstonLogger: winston.Logger) {
    this.winston = winstonLogger;
  }

  // Standard logging methods
  error(message: string, meta?: any): void {
    this.winston.error(message, meta);
  }

  warn(message: string, meta?: any): void {
    this.winston.warn(message, meta);
  }

  info(message: string, meta?: any): void {
    this.winston.info(message, meta);
  }

  http(message: string, meta?: any): void {
    this.winston.http(message, meta);
  }

  debug(message: string, meta?: any): void {
    this.winston.debug(message, meta);
  }


  // Enhanced logging methods with context
  logRequest(req: any, res: any, responseTime?: number): void {
    const meta = {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id,
      responseTime: responseTime ? `${responseTime}ms` : undefined,
    };

    this.http(`${req.method} ${req.originalUrl} ${res.statusCode}`, meta);
  }

  logClaimActivity(claimId: string, action: string, userId: string, details?: any): void {
    const meta = {
      claimId,
      action,
      userId,
      timestamp: new Date().toISOString(),
      ...details,
    };

    this.info(`Claim activity: ${action}`, meta);
  }

  logFraudDetection(claimId: string, fraudScore: number, patterns: string[], details?: any): void {
    const meta = {
      claimId,
      fraudScore,
      patterns,
      timestamp: new Date().toISOString(),
      ...details,
    };

    if (fraudScore > config.constants.fraudScoreThreshold) {
      this.warn(`High fraud score detected for claim ${claimId}`, meta);
    } else {
      this.info(`Fraud analysis completed for claim ${claimId}`, meta);
    }
  }

  logSettlement(settlementId: string, amount: number, providerId: string, status: string, details?: any): void {
    const meta = {
      settlementId,
      amount,
      providerId,
      status,
      timestamp: new Date().toISOString(),
      ...details,
    };

    this.info(`Settlement ${status}: ${settlementId}`, meta);
  }

  logBlockchainTransaction(txHash: string, operation: string, gasUsed?: number, details?: any): void {
    const meta = {
      txHash,
      operation,
      gasUsed,
      network: config.blockchain.network,
      timestamp: new Date().toISOString(),
      ...details,
    };

    this.info(`Blockchain transaction: ${operation}`, meta);
  }

  logSecurityEvent(event: string, severity: 'low' | 'medium' | 'high' | 'critical', details?: any): void {
    const meta = {
      event,
      severity,
      timestamp: new Date().toISOString(),
      ...details,
    };

    switch (severity) {
      case 'critical':
      case 'high':
        this.error(`Security event: ${event}`, meta);
        break;
      case 'medium':
        this.warn(`Security event: ${event}`, meta);
        break;
      case 'low':
      default:
        this.info(`Security event: ${event}`, meta);
        break;
    }
  }

  logPerformance(operation: string, duration: number, details?: any): void {
    const meta = {
      operation,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
      ...details,
    };

    if (duration > 5000) { // Log slow operations (>5s)
      this.warn(`Slow operation detected: ${operation}`, meta);
    } else {
      this.debug(`Performance: ${operation}`, meta);
    }
  }

  logDatabaseQuery(query: string, duration: number, rowCount?: number): void {
    const meta = {
      query: query.substring(0, 200) + (query.length > 200 ? '...' : ''),
      duration: `${duration}ms`,
      rowCount,
      timestamp: new Date().toISOString(),
    };

    if (duration > 1000) { // Log slow queries (>1s)
      this.warn('Slow database query detected', meta);
    } else {
      this.debug('Database query executed', meta);
    }
  }

  logAPICall(service: string, endpoint: string, method: string, statusCode: number, duration: number, details?: any): void {
    const meta = {
      service,
      endpoint,
      method,
      statusCode,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
      ...details,
    };

    if (statusCode >= 400) {
      this.error(`External API error: ${service}`, meta);
    } else if (duration > 3000) {
      this.warn(`Slow external API call: ${service}`, meta);
    } else {
      this.debug(`External API call: ${service}`, meta);
    }
  }

  // Structured error logging
  logError(error: Error, context?: string, details?: any): void {
    const meta = {
      name: error.name,
      message: error.message,
      stack: error.stack,
      context,
      timestamp: new Date().toISOString(),
      ...details,
    };

    this.error(`Error${context ? ` in ${context}` : ''}: ${error.message}`, meta);
  }

  // Business logic logging
  logBusinessEvent(event: string, entityType: string, entityId: string, details?: any): void {
    const meta = {
      event,
      entityType,
      entityId,
      timestamp: new Date().toISOString(),
      ...details,
    };

    this.info(`Business event: ${event}`, meta);
  }

  // Audit logging
  logAudit(action: string, userId: string, resource: string, resourceId: string, changes?: any): void {
    const meta = {
      action,
      userId,
      resource,
      resourceId,
      changes,
      timestamp: new Date().toISOString(),
      ip: 'unknown', // This should be passed from request context
    };

    this.info(`Audit: ${action} on ${resource}`, meta);
  }
}

// Create enhanced logger instance
const enhancedLogger = new Logger(logger);

// Export both the winston logger and enhanced logger
export { logger as winstonLogger, stream };
export default enhancedLogger;
export const log = enhancedLogger;

// Performance monitoring helper
export const performanceLogger = {
  start: (operation: string) => {
    const startTime = Date.now();
    return {
      end: (details?: any) => {
        const duration = Date.now() - startTime;
        enhancedLogger.logPerformance(operation, duration, details);
        return duration;
      },
    };
  },
};

// Database query logger helper
export const queryLogger = {
  log: (query: string, startTime: number, rowCount?: number) => {
    const duration = Date.now() - startTime;
    enhancedLogger.logDatabaseQuery(query, duration, rowCount);
  },
};

// API call logger helper
export const apiLogger = {
  log: (service: string, endpoint: string, method: string, statusCode: number, startTime: number, details?: any) => {
    const duration = Date.now() - startTime;
    enhancedLogger.logAPICall(service, endpoint, method, statusCode, duration, details);
  },
};