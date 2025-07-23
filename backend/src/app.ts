// Main application setup - August Insurance Claims API
// TODO: Maybe refactor this into smaller modules later?
import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import morgan from 'morgan';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';

import { config } from './config';
import logger from './utils/logger';
import databaseService from './services/DatabaseService';
import redisService from './services/RedisService';
import blockchainService from './services/BlockchainService';
import {
  errorHandler,
  notFoundHandler,
  timeoutHandler
} from './middleware/errorHandler';
import { sanitizeInput, validateRequestSize } from './middleware/validation';

// Import routes
import authRoutes from './routes/auth';
import claimsRoutes from './routes/claims';
import providersRoutes from './routes/providers';
import policiesRoutes from './routes/policies';
import settlementsRoutes from './routes/settlements';
import fraudRoutes from './routes/fraud';
import multisigRoutes from './routes/multisig';

class App {
  public app: Application;
  private server: any; // yeah I know, should type this properly

  constructor() {
    this.app = express();
    // Order matters here - learned this the hard way
    this.initializeMiddleware();
    this.initializeSwagger();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddleware(): void {
    // Security first! Helmet is a lifesaver
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], // unsafe-inline needed for swagger
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'https:'],
          scriptSrc: ["'self'"],
          connectSrc: ["'self'", config.frontend.url]
        }
      },
      crossOriginEmbedderPolicy: false // had to disable this for some reason
    }));

    // CORS - this was a pain to get right
    this.app.use(cors({
      origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
          config.frontend.url,
          'http://localhost:3000',
          'http://localhost:3001', // for testing
          'https://localhost:3000',
          'https://localhost:3001'
        ];
        
        if (allowedOrigins.includes(origin) || config.env === 'development') {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
      exposedHeaders: ['X-Total-Count', 'X-Page-Count']
    }));

    // Compression
      this.app.use(compression({
        filter: (req: Request, res: Response) => {
          if (req.headers['x-no-compression']) {
            return false;
          }
          return compression.filter(req, res);
        },
        threshold: 1024
      }));

    // Request parsing
    this.app.use(express.json({ 
      limit: config.upload.maxFileSize,
      verify: (req: any, res, buf) => {
        req.rawBody = buf;
      }
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: config.upload.maxFileSize 
    }));

    // Request size validation
    this.app.use(validateRequestSize);

    // Input sanitization
    this.app.use(sanitizeInput);

    // Request timeout
    this.app.use(timeoutHandler());

    // Logging
    if (config.env === 'production') {
      this.app.use(morgan('combined', {
        stream: {
          write: (message: string) => {
            logger.info(message.trim(), { component: 'http' });
          }
        },
        skip: (req: Request) => {
          // Skip health check logs
          return req.url === '/health' || req.url === '/api/health';
        }
      }));
    } else {
      this.app.use(morgan('dev'));
    }

    // Rate limiting
    const limiter = rateLimit({
      windowMs: config.rateLimit.windowMs,
      max: config.rateLimit.maxRequests,
      message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req: Request) => {
        // Skip rate limiting for health checks
        return req.url === '/health' || req.url === '/api/health';
      },
      keyGenerator: (req: Request) => {
        // Use user ID if authenticated, otherwise IP
        return (req as any).user?.id || req.ip;
      }
    });

    this.app.use(limiter);

    // Speed limiting (slow down repeated requests)
    const speedLimiter = slowDown({
      windowMs: 15 * 60 * 1000, // 15 minutes
      delayAfter: 50, // Allow 50 requests per windowMs without delay
      delayMs: 500, // Add 500ms delay per request after delayAfter
      maxDelayMs: 20000, // Maximum delay of 20 seconds
      skip: (req: Request) => {
        return req.url === '/health' || req.url === '/api/health';
      }
    });

    this.app.use(speedLimiter);

    // Trust proxy (for accurate IP addresses behind load balancers)
    this.app.set('trust proxy', 1);

    // Custom middleware for request tracking
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      const requestId = Math.random().toString(36).substring(2, 15);
      (req as any).requestId = requestId;
      res.setHeader('X-Request-ID', requestId);
      
      const startTime = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info('Request completed', {
          requestId,
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration,
          userAgent: req.get('User-Agent'),
          ip: req.ip,
          userId: (req as any).user?.id
        });
      });
      
      next();
    });
  }

  private initializeSwagger(): void {
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'Augustium Health Insurance Claims API',
          version: '1.0.0',
          description: `
            A comprehensive health insurance claims processing system built on the Augustium blockchain platform.
            
            ## Features
            - **Automated Claim Verification**: Smart contract-based claim validation
            - **Fraud Detection**: AI-powered pattern analysis and risk assessment
            - **Multi-Signature Approvals**: Secure approval workflows for high-value claims
            - **Real-time Settlements**: Instant payment processing with healthcare providers
            - **Blockchain Integration**: Immutable audit trails and transparent processing
            
            ## Authentication
            This API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:
            \`Authorization: Bearer <your-jwt-token>\`
            
            ## Rate Limiting
            API requests are rate-limited to ensure fair usage and system stability.
            
            ## Error Handling
            All errors follow a consistent format with appropriate HTTP status codes and descriptive messages.
          `,
          contact: {
            name: 'Augustium Insurance API Support',
            email: 'api-support@augustium-insurance.com'
          },
          license: {
            name: 'MIT',
            url: 'https://opensource.org/licenses/MIT'
          }
        },
        servers: [
          {
            url: config.env === 'production' 
              ? `https://localhost:${config.port}/api`
              : `http://localhost:${config.port}/api`,
            description: config.env === 'production' ? 'Production server' : 'Development server'
          }
        ],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
              description: 'Enter your JWT token'
            }
          },
          schemas: {
            Error: {
              type: 'object',
              properties: {
                error: {
                  type: 'string',
                  description: 'Error message'
                },
                code: {
                  type: 'string',
                  description: 'Error code'
                },
                details: {
                  type: 'object',
                  description: 'Additional error details'
                },
                timestamp: {
                  type: 'string',
                  format: 'date-time',
                  description: 'Error timestamp'
                },
                requestId: {
                  type: 'string',
                  description: 'Request identifier for tracking'
                }
              }
            },
            PaginationInfo: {
              type: 'object',
              properties: {
                page: {
                  type: 'integer',
                  description: 'Current page number'
                },
                limit: {
                  type: 'integer',
                  description: 'Items per page'
                },
                total: {
                  type: 'integer',
                  description: 'Total number of items'
                },
                totalPages: {
                  type: 'integer',
                  description: 'Total number of pages'
                },
                hasNext: {
                  type: 'boolean',
                  description: 'Whether there are more pages'
                },
                hasPrev: {
                  type: 'boolean',
                  description: 'Whether there are previous pages'
                }
              }
            }
          }
        },
        tags: [
          {
            name: 'Authentication',
            description: 'User authentication and session management'
          },
          {
            name: 'Claims',
            description: 'Insurance claim submission and processing'
          },
          {
            name: 'Providers',
            description: 'Healthcare provider management'
          },
          {
            name: 'Policies',
            description: 'Insurance policy management'
          },
          {
            name: 'Settlements',
            description: 'Payment settlement processing'
          },
          {
            name: 'Fraud Detection',
            description: 'Fraud analysis and pattern detection'
          },
          {
            name: 'Multi-Signature Approvals',
            description: 'Multi-signature approval workflows'
          }
        ]
      },
      apis: ['./src/routes/*.ts'], // Path to the API files
    };

    const swaggerSpec = (swaggerJsdoc as any)(swaggerOptions);

    // Serve Swagger UI
    this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'Augustium Insurance API Documentation',
      swaggerOptions: {
        persistAuthorization: true,
        displayRequestDuration: true,
        filter: true,
        showExtensions: true,
        showCommonExtensions: true
      }
    }));

    // Serve raw swagger spec
    this.app.get('/api-docs.json', (req: Request, res: Response) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(swaggerSpec);
    });
  }

  private initializeRoutes(): void {
    // Health check endpoint
    this.app.get('/health', async (req: Request, res: Response) => {
      try {
        const healthChecks = await Promise.allSettled([
          databaseService.healthCheck(),
          redisService.healthCheck()
        ]);

        const dbHealth = healthChecks[0];
        const redisHealth = healthChecks[1];
        let blockchainHealth: any = null;

        // Only check blockchain health if it's enabled
        if (config.env !== 'development' || process.env['ENABLE_BLOCKCHAIN'] === 'true') {
          const blockchainHealthCheck = await Promise.allSettled([blockchainService.healthCheck()]);
          blockchainHealth = blockchainHealthCheck[0];
        }

        const overallHealth = 
          dbHealth.status === 'fulfilled' && 
          redisHealth.status === 'fulfilled' && 
          (blockchainHealth === null || blockchainHealth.status === 'fulfilled');

        const healthStatus = {
          status: overallHealth ? 'healthy' : 'unhealthy',
          timestamp: new Date().toISOString(),
          version: process.env['npm_package_version'] || '1.0.0',
          environment: config.env,
          services: {
            database: {
              status: dbHealth.status === 'fulfilled' ? 'healthy' : 'unhealthy',
              details: dbHealth.status === 'fulfilled' ? dbHealth.value : dbHealth.reason?.message
            },
            redis: {
              status: redisHealth.status === 'fulfilled' ? 'healthy' : 'unhealthy',
              details: redisHealth.status === 'fulfilled' ? redisHealth.value : redisHealth.reason?.message
            },
            blockchain: {
              status: blockchainHealth === null ? 'disabled' : (blockchainHealth.status === 'fulfilled' ? 'healthy' : 'unhealthy'),
              details: blockchainHealth === null ? 'Disabled in development mode' : (blockchainHealth.status === 'fulfilled' ? blockchainHealth.value : blockchainHealth.reason?.message)
            }
          },
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage()
        };

        res.status(overallHealth ? 200 : 503).json(healthStatus);
      } catch (error: unknown) {
        logger.error('Health check failed', { error: error instanceof Error ? error.message : String(error) });
        res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          error: 'Health check failed'
        });
      }
    });

    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/claims', claimsRoutes);
    this.app.use('/api/providers', providersRoutes);
    this.app.use('/api/policies', policiesRoutes);
    this.app.use('/api/settlements', settlementsRoutes);
    this.app.use('/api/fraud', fraudRoutes);
    this.app.use('/api/multisig', multisigRoutes);

    // Root endpoint
    this.app.get('/', (req: Request, res: Response) => {
      res.json({
        message: 'Augustium Health Insurance Claims API',
        version: process.env['npm_package_version'] || '1.0.0',
        environment: config.env,
        documentation: '/api-docs',
        health: '/health',
        timestamp: new Date().toISOString()
      });
    });

    // API info endpoint
    this.app.get('/api', (req: Request, res: Response) => {
      res.json({
        message: 'Augustium Health Insurance Claims API',
        version: process.env['npm_package_version'] || '1.0.0',
        environment: config.env,
        endpoints: {
          authentication: '/api/auth',
          claims: '/api/claims',
          providers: '/api/providers',
          policies: '/api/policies',
          settlements: '/api/settlements',
          fraud: '/api/fraud',
          multisig: '/api/multisig'
        },
        documentation: '/api-docs',
        health: '/health',
        timestamp: new Date().toISOString()
      });
    });
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use(notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);
  }

  public async start(): Promise<void> {
    try {
      // Initialize services
      logger.info('Initializing services...');
      
      await databaseService.initialize();
      logger.info('Database service initialized');
      
      await redisService.initialize();
      logger.info('Redis service initialized');
      
      // Only initialize blockchain service if not in development or if explicitly enabled
      if (config.env !== 'development' || process.env['ENABLE_BLOCKCHAIN'] === 'true') {
        await blockchainService.initialize();
        logger.info('Blockchain service initialized');
      } else {
        logger.info('Blockchain service skipped in development mode');
      }

      // Start server
      this.server = this.app.listen(config.port, () => {
        logger.info(`Server started successfully`, {
          port: config.port,
          environment: config.env,
          documentation: `http://localhost:${config.port}/api-docs`,
          health: `http://localhost:${config.port}/health`
        });
      });

      // Handle server errors
      this.server.on('error', (error: any) => {
        if (error.code === 'EADDRINUSE') {
          logger.error(`Port ${config.port} is already in use`);
        } else {
          logger.error('Server error', { error: error.message });
        }
        process.exit(1);
      });

      // Graceful shutdown handlers
      process.on('SIGTERM', () => this.gracefulShutdown('SIGTERM'));
      process.on('SIGINT', () => this.gracefulShutdown('SIGINT'));
      process.on('SIGUSR2', () => this.gracefulShutdown('SIGUSR2')); // Nodemon restart

    } catch (error: unknown) {
      logger.error('Failed to start server', { error: error instanceof Error ? error.message : String(error) });
      process.exit(1);
    }
  }

  private async gracefulShutdown(signal: string): Promise<void> {
    logger.info(`Received ${signal}, starting graceful shutdown...`);

    // Stop accepting new requests
    if (this.server) {
      this.server.close(async () => {
        logger.info('HTTP server closed');

        try {
          // Close service connections
          const closePromises = [
            databaseService.close(),
            redisService.close()
          ];
          
          // Only close blockchain service if it was initialized
          if (config.env !== 'development' || process.env['ENABLE_BLOCKCHAIN'] === 'true') {
            closePromises.push(blockchainService.close());
          }
          
          await Promise.all(closePromises);

          logger.info('All services disconnected successfully');
          process.exit(0);
        } catch (error: unknown) {
        logger.error('Error during graceful shutdown', { error: error instanceof Error ? error.message : String(error) });
          process.exit(1);
        }
      });

      // Force close after timeout
      setTimeout(() => {
        logger.error('Graceful shutdown timeout, forcing exit');
        process.exit(1);
      }, 30000); // 30 seconds timeout
    } else {
      process.exit(0);
    }
  }

  public getApp(): Application {
    return this.app;
  }

  public getServer(): any {
    return this.server;
  }
}

export default App;