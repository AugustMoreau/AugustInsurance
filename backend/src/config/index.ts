import * as dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables first thing
dotenv.config();

// TODO: maybe switch to a different env validation library? zod is overkill but works

// Environment validation schema
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().default('8080').transform(Number),

  // Database config - using PostgreSQL because it's reliable
  DATABASE_URL: z.string().default('postgresql://localhost:5432/augustinsurance'),
  DATABASE_HOST: z.string().default('localhost'),
  DATABASE_PORT: z.string().default('5432').transform(Number),
  DATABASE_NAME: z.string().default('augustinsurance'),
  DATABASE_USER: z.string().default('postgres'),
  DATABASE_PASSWORD: z.string().default('password'), // change this in prod obviously
  DATABASE_SSL: z.string().default('false').transform(val => val === 'true'),
  DATABASE_POOL_MIN: z.string().default('2').transform(Number),
  DATABASE_POOL_MAX: z.string().default('10').transform(Number),

  // Redis configuration
  REDIS_URL: z.string().default('redis://localhost:6379'),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().default('6379').transform(Number),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().default('0').transform(Number),

  // JWT stuff - probably should use shorter expiry times
  JWT_SECRET: z.string().default('your-super-secret-jwt-key-change-in-production'),
  JWT_EXPIRES_IN: z.string().default('24h'), // 24h might be too long?
  JWT_REFRESH_SECRET: z.string().default('your-super-secret-refresh-key-change-in-production'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Blockchain configuration
  BLOCKCHAIN_NETWORK: z.string().default('testnet'),
  BLOCKCHAIN_RPC_URL: z.string().default('http://localhost:8545'),
  BLOCKCHAIN_PRIVATE_KEY: z.string().default('0x0000000000000000000000000000000000000000000000000000000000000000'),
  BLOCKCHAIN_CONTRACT_ADDRESS: z.string().default('0x0000000000000000000000000000000000000000'),
  BLOCKCHAIN_GAS_LIMIT: z.string().default('500000').transform(Number),
  BLOCKCHAIN_GAS_PRICE: z.string().default('20000000000'),

  // Email configuration
  SMTP_HOST: z.string().default('smtp.gmail.com'),
  SMTP_PORT: z.string().default('587').transform(Number),
  SMTP_USER: z.string().default('noreply@augustinsurance.com'),
  SMTP_PASSWORD: z.string().default('your-email-password'),
  SMTP_FROM: z.string().default('AugustInsurance <noreply@augustinsurance.com>'),

  // AWS configuration
  AWS_REGION: z.string().default('us-east-1'),
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_S3_BUCKET: z.string().default('augustinsurance-documents'),

  // ML Service configuration
  ML_SERVICE_URL: z.string().default('http://localhost:5000'),
  ML_SERVICE_API_KEY: z.string().default('ml-service-api-key'),
  ML_MODEL_VERSION: z.string().default('v1.0'),

  // External APIs
  EXTERNAL_VERIFICATION_API_URL: z.string().default('https://api.verification-service.com'),
  EXTERNAL_VERIFICATION_API_KEY: z.string().default('verification-api-key'),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: z.string().default('900000').transform(Number), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().default('100').transform(Number),

  // File upload
  MAX_FILE_SIZE: z.string().default('10485760').transform(Number), // 10MB
  ALLOWED_FILE_TYPES: z.string().default('pdf,jpg,jpeg,png,doc,docx'),

  // Monitoring
  SENTRY_DSN: z.string().optional(),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),

  // Frontend URL
  FRONTEND_URL: z.string().default('http://localhost:3001'),

  // API Configuration
  API_BASE_URL: z.string().default('http://localhost:8080'),
  API_VERSION: z.string().default('v1'),

  // Security
  ENCRYPTION_KEY: z.string().default('your-32-character-encryption-key!!'),
  CORS_ORIGINS: z.string().default('http://localhost:3001,http://localhost:8080'),

  // Payment processing
  PAYMENT_PROCESSOR_URL: z.string().default('https://api.payment-processor.com'),
  PAYMENT_PROCESSOR_API_KEY: z.string().default('payment-processor-api-key'),

  // Notification services
  TWILIO_ACCOUNT_SID: z.string().optional(),
  TWILIO_AUTH_TOKEN: z.string().optional(),
  TWILIO_PHONE_NUMBER: z.string().optional(),

  // Webhook configuration
  WEBHOOK_SECRET: z.string().default('webhook-secret-key'),

  // Cache configuration
  CACHE_TTL: z.string().default('3600').transform(Number), // 1 hour

  // Queue configuration
  QUEUE_REDIS_URL: z.string().optional(),
  QUEUE_CONCURRENCY: z.string().default('5').transform(Number),
});

// Validate environment variables
const env = envSchema.parse(process.env);

// Configuration object
export const config = {
  env: env.NODE_ENV,
  port: env.PORT,

  // Database configuration
  database: {
    url: env.DATABASE_URL,
    host: env.DATABASE_HOST,
    port: env.DATABASE_PORT,
    name: env.DATABASE_NAME,
    user: env.DATABASE_USER,
    password: env.DATABASE_PASSWORD,
    ssl: env.DATABASE_SSL,
    pool: {
      min: env.DATABASE_POOL_MIN,
      max: env.DATABASE_POOL_MAX,
    },
  },

  // Redis configuration
  redis: {
    url: env.REDIS_URL,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
  },

  // JWT configuration
  jwt: {
    secret: env.JWT_SECRET,
    expiresIn: env.JWT_EXPIRES_IN,
    refreshSecret: env.JWT_REFRESH_SECRET,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
  },

  // Blockchain configuration
  blockchain: {
    network: env.BLOCKCHAIN_NETWORK,
    rpcUrl: env.BLOCKCHAIN_RPC_URL,
    privateKey: env.BLOCKCHAIN_PRIVATE_KEY,
    contractAddress: env.BLOCKCHAIN_CONTRACT_ADDRESS,
    gasLimit: env.BLOCKCHAIN_GAS_LIMIT,
    gasPrice: env.BLOCKCHAIN_GAS_PRICE,
  },

  // Email configuration
  email: {
    smtp: {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      user: env.SMTP_USER,
      password: env.SMTP_PASSWORD,
      from: env.SMTP_FROM,
    },
  },

  // AWS configuration
  aws: {
    region: env.AWS_REGION,
    accessKeyId: env.AWS_ACCESS_KEY_ID,
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    s3: {
      bucket: env.AWS_S3_BUCKET,
    },
  },

  // ML Service configuration
  ml: {
    serviceUrl: env.ML_SERVICE_URL,
    apiKey: env.ML_SERVICE_API_KEY,
    modelVersion: env.ML_MODEL_VERSION,
  },

  // External APIs
  external: {
    verification: {
      url: env.EXTERNAL_VERIFICATION_API_URL,
      apiKey: env.EXTERNAL_VERIFICATION_API_KEY,
    },
  },

  // Rate limiting
  rateLimit: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
  },

  // File upload
  upload: {
    maxFileSize: env.MAX_FILE_SIZE,
    allowedTypes: env.ALLOWED_FILE_TYPES.split(',').map(type => type.trim()),
  },

  // Monitoring
  monitoring: {
    sentryDsn: env.SENTRY_DSN,
    logLevel: env.LOG_LEVEL,
  },

  // Frontend configuration
  frontend: {
    url: env.FRONTEND_URL,
  },

  // API configuration
  api: {
    baseUrl: env.API_BASE_URL,
    version: env.API_VERSION,
  },

  // Security
  security: {
    encryptionKey: env.ENCRYPTION_KEY,
    webhookSecret: env.WEBHOOK_SECRET,
  },

  // CORS configuration
  cors: {
    allowedOrigins: env.CORS_ORIGINS.split(',').map(origin => origin.trim()),
  },

  // Payment processing
  payment: {
    processorUrl: env.PAYMENT_PROCESSOR_URL,
    apiKey: env.PAYMENT_PROCESSOR_API_KEY,
  },

  // Notification services
  notifications: {
    twilio: {
      accountSid: env.TWILIO_ACCOUNT_SID,
      authToken: env.TWILIO_AUTH_TOKEN,
      phoneNumber: env.TWILIO_PHONE_NUMBER,
    },
  },

  // Cache configuration
  cache: {
    ttl: env.CACHE_TTL,
  },

  // Queue configuration
  queue: {
    redisUrl: env.QUEUE_REDIS_URL || env.REDIS_URL,
    concurrency: env.QUEUE_CONCURRENCY,
  },

  // Application constants
  constants: {
    // Claim processing
    autoApprovalThreshold: 1000, // Claims under $1000 auto-approved
    largeClaimThreshold: 10000, // Claims over $10000 require multi-sig
    fraudScoreThreshold: 0.7, // Fraud score threshold for flagging

    // Settlement processing
    immediateSettlementThreshold: 5000, // Settlements under $5000 processed immediately
    batchSettlementInterval: 3600000, // 1 hour in milliseconds

    // Multi-signature approvals
    requiredApprovers: {
      small: 1, // Claims $1000-$10000
      medium: 2, // Claims $10000-$50000
      large: 3, // Claims $50000+
      emergency: 1, // Emergency overrides
    },

    // Fraud detection
    fraudPatterns: {
      frequencyThreshold: 5, // Max claims per month
      amountVarianceThreshold: 0.3, // 30% variance in claim amounts
      timeWindowHours: 24, // Time window for pattern analysis
      geographicRadiusKm: 50, // Geographic radius for location analysis
    },

    // File processing
    documentRetentionDays: 2555, // 7 years
    maxDocumentsPerClaim: 10,

    // API limits
    maxPageSize: 100,
    defaultPageSize: 20,

    // Session management
    sessionTimeoutMinutes: 30,
    maxConcurrentSessions: 5,
  },
};

// Validation functions
export const validateConfig = () => {
  const requiredInProduction = [
    'JWT_SECRET',
    'DATABASE_URL',
    'REDIS_URL',
    'BLOCKCHAIN_PRIVATE_KEY',
  ];

  if (config.env === 'production') {
    for (const key of requiredInProduction) {
      if (!process.env[key] || process.env[key] === `your-${key.toLowerCase().replace('_', '-')}-change-in-production`) {
        throw new Error(`${key} must be set in production environment`);
      }
    }
  }
};

// Export individual configurations for easier imports
export const {
  database,
  redis,
  jwt,
  blockchain,
  email,
  aws,
  ml,
  external,
  rateLimit,
  upload,
  monitoring,
  frontend,
  api,
  security,
  cors,
  payment,
  notifications,
  cache,
  queue,
  constants,
} = config;

export default config;