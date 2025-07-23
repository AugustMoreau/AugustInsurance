import type { Request, Response, NextFunction } from 'express';
import * as Joi from 'joi';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';
import logger from '../utils/logger';

// Initialize DOMPurify with JSDOM
const { window } = new JSDOM('');
const DOMPurify = createDOMPurify(window as any);

// Use standard Joi for validation
const customJoi = Joi;

// Custom validation functions
const validateCreditCard = (value: string) => {
  const cleaned = value.replace(/\D/g, '');
  if (cleaned.length < 13 || cleaned.length > 19) {
    return false;
  }

  let sum = 0;
  let isEven = false;

  for (let i = cleaned.length - 1; i >= 0; i--) {
    const char = cleaned.charAt(i);
    if (!char) {
      return false;
    }
    let digit = parseInt(char);
    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
};

const validatePhone = (value: string) => {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  const cleaned = value.replace(/[^\d+]/g, '');
  return phoneRegex.test(cleaned);
};

const validateSSN = (value: string) => {
  const ssnRegex = /^\d{3}-?\d{2}-?\d{4}$/;
  return ssnRegex.test(value);
};

const validateNPI = (value: string) => {
  const cleanedNpi = value.replace(/\D/g, '');
  if (cleanedNpi.length !== 10) {
    return false;
  }

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    const char = cleanedNpi.charAt(i);
    if (!char) {
      return false;
    }
    let digit = parseInt(char);
    if (i % 2 === 1) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
  }

  const lastChar = cleanedNpi.charAt(9);
  if (!lastChar) {
    return false;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  return checkDigit === parseInt(lastChar);
};

// Common validation schemas
export const commonSchemas = {
  id: customJoi.string().uuid().required(),
  email: customJoi.string().email().max(255).required(),
  password: customJoi.string().min(8).max(128).pattern(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  ).required().messages({
    'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  }),
  phone: customJoi.string().custom((value, helpers) => {
    if (!validatePhone(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  }).required().messages({
    'any.invalid': 'must be a valid phone number',
  }),
  date: customJoi.date().iso().required(),
  amount: customJoi.number().positive().precision(2).max(1000000).required(),
  pagination: {
    page: customJoi.number().integer().min(1).default(1),
    limit: customJoi.number().integer().min(1).max(100).default(20),
    sortBy: customJoi.string().max(50).default('created_at'),
    sortOrder: customJoi.string().valid('asc', 'desc').default('desc'),
  },
};

// User validation schemas
export const userSchemas = {
  register: customJoi.object({
    email: commonSchemas.email,
    password: commonSchemas.password,
    firstName: customJoi.string().min(1).max(100).required(),
    lastName: customJoi.string().min(1).max(100).required(),
    phone: commonSchemas.phone,
    role: customJoi.string().valid(
      'admin', 'claims_processor', 'medical_director', 'financial_controller',
      'fraud_analyst', 'provider', 'patient', 'auditor',
    ).default('patient'),
    dateOfBirth: customJoi.date().max('now').required(),
    address: customJoi.object({
      street: customJoi.string().max(255).required(),
      city: customJoi.string().max(100).required(),
      state: customJoi.string().length(2).required(),
      zipCode: customJoi.string().pattern(/^\d{5}(-\d{4})?$/).required(),
      country: customJoi.string().length(2).default('US'),
    }).required(),
  }),

  login: customJoi.object({
    email: commonSchemas.email,
    password: customJoi.string().required(),
    rememberMe: customJoi.boolean().default(false),
  }),

  updateProfile: customJoi.object({
    firstName: customJoi.string().min(1).max(100),
    lastName: customJoi.string().min(1).max(100),
    phone: commonSchemas.phone,
    address: customJoi.object({
      street: customJoi.string().max(255),
      city: customJoi.string().max(100),
      state: customJoi.string().length(2),
      zipCode: customJoi.string().pattern(/^\d{5}(-\d{4})?$/),
      country: customJoi.string().length(2),
    }),
  }),

  changePassword: customJoi.object({
    currentPassword: customJoi.string().required(),
    newPassword: commonSchemas.password,
  }),
};

// Claim validation schemas
export const claimSchemas = {
  submit: customJoi.object({
    policyId: commonSchemas.id,
    providerId: commonSchemas.id,
    patientId: commonSchemas.id,
    serviceDate: commonSchemas.date,
    diagnosisCode: customJoi.string().pattern(/^[A-Z]\d{2}(\.\d{1,3})?$/).required(),
    procedureCode: customJoi.string().pattern(/^\d{5}$/).required(),
    amount: commonSchemas.amount,
    description: customJoi.string().max(1000).required(),
    urgency: customJoi.string().valid('low', 'medium', 'high', 'emergency').default('medium'),
    attachments: customJoi.array().items(
      customJoi.object({
        filename: customJoi.string().max(255).required(),
        contentType: customJoi.string().valid(
          'application/pdf', 'image/jpeg', 'image/png', 'image/tiff',
        ).required(),
        size: customJoi.number().max(10 * 1024 * 1024).required(), // 10MB max
        url: customJoi.string().uri().required(),
      }),
    ).max(10),
    metadata: customJoi.object({
      facilityType: customJoi.string().valid('hospital', 'clinic', 'emergency', 'outpatient'),
      admissionDate: customJoi.date(),
      dischargeDate: customJoi.date().min(customJoi.ref('admissionDate')),
      referralRequired: customJoi.boolean().default(false),
      priorAuthRequired: customJoi.boolean().default(false),
    }),
  }),

  review: customJoi.object({
    status: customJoi.string().valid('approved', 'rejected', 'pending_review').required(),
    reviewNotes: customJoi.string().max(2000),
    adjustedAmount: customJoi.number().positive().precision(2),
    reviewerId: commonSchemas.id,
  }),

  search: customJoi.object({
    ...commonSchemas.pagination,
    status: customJoi.string().valid('submitted', 'under_review', 'approved', 'rejected', 'settled'),
    providerId: customJoi.string().uuid(),
    patientId: customJoi.string().uuid(),
    dateFrom: customJoi.date().iso(),
    dateTo: customJoi.date().iso().min(customJoi.ref('dateFrom')),
    amountMin: customJoi.number().positive(),
    amountMax: customJoi.number().positive().min(customJoi.ref('amountMin')),
    urgency: customJoi.string().valid('low', 'medium', 'high', 'emergency'),
  }),
};

// Provider validation schemas
export const providerSchemas = {
  register: customJoi.object({
    name: customJoi.string().min(1).max(255).required(),
    npi: customJoi.string().custom((value, helpers) => {
      if (!validateNPI(value)) {
        return helpers.error('any.invalid');
      }
      return value;
    }).required().messages({
      'any.invalid': 'must be a valid NPI number',
    }),
    taxId: customJoi.string().pattern(/^\d{2}-\d{7}$/).required(),
    specialties: customJoi.array().items(
      customJoi.string().max(100),
    ).min(1).required(),
    contactInfo: customJoi.object({
      email: commonSchemas.email,
      phone: commonSchemas.phone,
      fax: customJoi.string().custom((value, helpers) => {
        if (!validatePhone(value)) {
          return helpers.error('any.invalid');
        }
        return value;
      }).messages({
        'any.invalid': 'must be a valid phone number',
      }),
      website: customJoi.string().uri(),
    }).required(),
    address: customJoi.object({
      street: customJoi.string().max(255).required(),
      city: customJoi.string().max(100).required(),
      state: customJoi.string().length(2).required(),
      zipCode: customJoi.string().pattern(/^\d{5}(-\d{4})?$/).required(),
      country: customJoi.string().length(2).default('US'),
    }).required(),
    credentials: customJoi.object({
      licenseNumber: customJoi.string().max(50).required(),
      licenseState: customJoi.string().length(2).required(),
      licenseExpiry: customJoi.date().greater('now').required(),
      boardCertifications: customJoi.array().items(
        customJoi.object({
          board: customJoi.string().max(100).required(),
          specialty: customJoi.string().max(100).required(),
          certificationDate: customJoi.date().required(),
          expiryDate: customJoi.date().greater('now').required(),
        }),
      ),
    }).required(),
    bankingInfo: customJoi.object({
      accountNumber: customJoi.string().pattern(/^\d{8,17}$/).required(),
      routingNumber: customJoi.string().pattern(/^\d{9}$/).required(),
      accountType: customJoi.string().valid('checking', 'savings').required(),
      bankName: customJoi.string().max(100).required(),
    }).required(),
  }),

  update: customJoi.object({
    name: customJoi.string().min(1).max(255),
    specialties: customJoi.array().items(
      customJoi.string().max(100),
    ).min(1),
    contactInfo: customJoi.object({
      email: commonSchemas.email,
      phone: commonSchemas.phone,
      fax: customJoi.string().custom((value, helpers) => {
        if (!validatePhone(value)) {
          return helpers.error('any.invalid');
        }
        return value;
      }).messages({
        'any.invalid': 'must be a valid phone number',
      }),
      website: customJoi.string().uri(),
    }),
    address: customJoi.object({
      street: customJoi.string().max(255),
      city: customJoi.string().max(100),
      state: customJoi.string().length(2),
      zipCode: customJoi.string().pattern(/^\d{5}(-\d{4})?$/),
      country: customJoi.string().length(2),
    }),
    bankingInfo: customJoi.object({
      accountNumber: customJoi.string().pattern(/^\d{8,17}$/),
      routingNumber: customJoi.string().pattern(/^\d{9}$/),
      accountType: customJoi.string().valid('checking', 'savings'),
      bankName: customJoi.string().max(100),
    }),
  }),
};

// Policy validation schemas
export const policySchemas = {
  create: customJoi.object({
    holderId: commonSchemas.id,
    policyNumber: customJoi.string().alphanum().min(8).max(20).required(),
    planType: customJoi.string().valid(
      'basic', 'standard', 'premium', 'family', 'individual',
    ).required(),
    coverageDetails: customJoi.object({
      deductible: customJoi.number().min(0).max(50000).required(),
      outOfPocketMax: customJoi.number().min(0).max(100000).required(),
      copayPrimary: customJoi.number().min(0).max(1000).required(),
      copaySpecialist: customJoi.number().min(0).max(1000).required(),
      coinsurance: customJoi.number().min(0).max(100).required(),
      prescriptionCoverage: customJoi.boolean().default(true),
      dentalCoverage: customJoi.boolean().default(false),
      visionCoverage: customJoi.boolean().default(false),
    }).required(),
    effectiveDate: customJoi.date().required(),
    expiryDate: customJoi.date().greater(customJoi.ref('effectiveDate')).required(),
    premiumAmount: customJoi.number().positive().precision(2).required(),
    dependents: customJoi.array().items(
      customJoi.object({
        firstName: customJoi.string().min(1).max(100).required(),
        lastName: customJoi.string().min(1).max(100).required(),
        dateOfBirth: customJoi.date().max('now').required(),
        relationship: customJoi.string().valid(
          'spouse', 'child', 'dependent',
        ).required(),
        ssn: customJoi.string().custom((value, helpers) => {
          if (!validateSSN(value)) {
            return helpers.error('any.invalid');
          }
          return value;
        }).required().messages({
          'any.invalid': 'must be a valid SSN format',
        }),
      }),
    ).max(10),
  }),

  update: customJoi.object({
    coverageDetails: customJoi.object({
      deductible: customJoi.number().min(0).max(50000),
      outOfPocketMax: customJoi.number().min(0).max(100000),
      copayPrimary: customJoi.number().min(0).max(1000),
      copaySpecialist: customJoi.number().min(0).max(1000),
      coinsurance: customJoi.number().min(0).max(100),
      prescriptionCoverage: customJoi.boolean(),
      dentalCoverage: customJoi.boolean(),
      visionCoverage: customJoi.boolean(),
    }),
    premiumAmount: customJoi.number().positive().precision(2),
    dependents: customJoi.array().items(
      customJoi.object({
        id: customJoi.string().uuid(),
        firstName: customJoi.string().min(1).max(100),
        lastName: customJoi.string().min(1).max(100),
        dateOfBirth: customJoi.date().max('now'),
        relationship: customJoi.string().valid(
          'spouse', 'child', 'dependent',
        ),
        ssn: customJoi.string().custom((value, helpers) => {
          if (!validateSSN(value)) {
            return helpers.error('any.invalid');
          }
          return value;
        }).messages({
          'any.invalid': 'must be a valid SSN format',
        }),
      }),
    ).max(10),
  }),
};

// Settlement validation schemas
export const settlementSchemas = {
  initiate: customJoi.object({
    claimId: commonSchemas.id,
    providerId: commonSchemas.id,
    amount: commonSchemas.amount,
    currency: customJoi.string().length(3).uppercase().default('USD'),
    settlementType: customJoi.string().valid('immediate', 'batch').default('immediate'),
    priority: customJoi.string().valid('low', 'medium', 'high').default('medium'),
    metadata: customJoi.object({
      reference: customJoi.string().max(100),
      notes: customJoi.string().max(500),
    }),
  }),

  process: customJoi.object({
    status: customJoi.string().valid('processed', 'failed', 'cancelled').required(),
    transactionId: customJoi.string().max(100),
    processingNotes: customJoi.string().max(1000),
    fees: customJoi.object({
      processingFee: customJoi.number().min(0).precision(2),
      networkFee: customJoi.number().min(0).precision(2),
      totalFees: customJoi.number().min(0).precision(2),
    }),
  }),
};

// Multi-signature approval schemas
export const approvalSchemas = {
  create: customJoi.object({
    claimId: commonSchemas.id,
    amount: commonSchemas.amount,
    urgency: customJoi.string().valid('low', 'medium', 'high', 'emergency').required(),
    requiredApprovers: customJoi.array().items(
      customJoi.string().valid(
        'medical_director', 'financial_controller', 'fraud_analyst', 'admin',
      ),
    ).min(1).required(),
    deadline: customJoi.date().greater('now').required(),
    description: customJoi.string().max(1000).required(),
  }),

  vote: customJoi.object({
    decision: customJoi.string().valid('approve', 'reject').required(),
    comments: customJoi.string().max(1000),
    conditions: customJoi.array().items(
      customJoi.string().max(200),
    ).max(5),
  }),
};

// Validation middleware factory
export const validate = (schema: Joi.ObjectSchema, source: 'body' | 'query' | 'params' = 'body') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const data = req[source];

    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
    });

    if (error) {
      const validationErrors = error.details.map((detail: Joi.ValidationErrorItem) => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value,
      }));

      logger.debug('Validation failed', {
        source,
        errors: validationErrors,
        originalData: data,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(400).json({
        error: 'Validation failed',
        message: 'The provided data is invalid',
        details: validationErrors,
      });
      return;
    }

    // Replace the original data with validated and sanitized data
    req[source] = value;
    next();
  };
};

// Sanitization middleware
export const sanitizeInput = (req: Request, res: Response, next: NextFunction): void => {
  const sanitizeObject = (obj: any): any => {
    if (typeof obj === 'string') {
      return DOMPurify.sanitize(obj, { ALLOWED_TAGS: [] });
    }

    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }

    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitizeObject(value);
      }
      return sanitized;
    }

    return obj;
  };

  // Sanitize request body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }

  // Sanitize URL parameters
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  next();
};

// File upload validation
export const validateFileUpload = (options: {
  maxSize?: number;
  allowedTypes?: string[];
  maxFiles?: number;
} = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB
    allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'],
    maxFiles = 10,
  } = options;

  return (req: Request & { files?: any }, res: Response, next: NextFunction): void => {
    if (!req.files || (Array.isArray(req.files) && req.files.length === 0)) {
      next();
      return;
    }

    const files = Array.isArray(req.files) ? req.files : [req.files];

    if (files.length > maxFiles) {
      res.status(400).json({
        error: 'Too many files',
        message: `Maximum ${maxFiles} files allowed`,
      });
      return;
    }

    for (const file of files) {
      if (file.size > maxSize) {
        res.status(400).json({
          error: 'File too large',
          message: `File ${file.name} exceeds maximum size of ${maxSize / (1024 * 1024)}MB`,
        });
        return;
      }

      if (!allowedTypes.includes(file.mimetype)) {
        res.status(400).json({
          error: 'Invalid file type',
          message: `File ${file.name} has invalid type. Allowed types: ${allowedTypes.join(', ')}`,
        });
        return;
      }
    }

    next();
  };
};

// Request size validation
export const validateRequestSize = (maxSize: number = 1024 * 1024) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = parseInt(req.get('content-length') || '0');

    if (contentLength > maxSize) {
      res.status(413).json({
        error: 'Request too large',
        message: `Request size exceeds maximum of ${maxSize / (1024 * 1024)}MB`,
      });
      return;
    }

    next();
  };
};

// IP whitelist validation
export const validateIPWhitelist = (whitelist: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIP = req.ip || 'unknown';

    if (!whitelist.includes(clientIP)) {
      logger.logSecurityEvent('IP not whitelisted', 'high', {
        ip: clientIP,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
      });

      res.status(403).json({
        error: 'Access denied',
        message: 'Your IP address is not authorized to access this resource',
      });
      return;
    }

    next();
  };
};

// All schemas are already exported above