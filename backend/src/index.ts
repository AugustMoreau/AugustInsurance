import * as express from 'express';
import * as cors from 'cors';
import * as helmet from 'helmet';
import * as morgan from 'morgan';
import * as compression from 'compression';
import * as rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import * as dotenv from 'dotenv';
import * as swaggerJsdoc from 'swagger-jsdoc';
import * as swaggerUi from 'swagger-ui-express';

// Import routes
import authRoutes from './routes/auth';
import claimsRoutes from './routes/claims';
import providersRoutes from './routes/providers';
import policiesRoutes from './routes/policies';
import settlementsRoutes from './routes/settlements';
import fraudRoutes from './routes/fraud';
import multisigRoutes from './routes/multisig';

// Import middleware
import { errorHandler } from './middleware/errorHandler';
import { authMiddleware } from './middleware/auth';
import { validateRequestSize } from './middleware/validation';

// Import services
import databaseService from './services/DatabaseService';
import redisService from './services/RedisService';
import blockchainService from './services/BlockchainService';

// Import utilities
import logger from './utils/logger';
import { config } from './config';

// Load environment variables
dotenv.config();

class AugustInsuranceServer {
  private app: express.Application;
  private server: any;
  private io: Server;
  private port: number;

  constructor() {
    this.app = (express as any)();
    this.port = config.port || 3000;
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: config.frontend.url,
        methods: ['GET', 'POST'],
        credentials: true
      }
    });

    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeSwagger();
    this.initializeErrorHandling();
    this.initializeSocketIO();
  }

  private initializeMiddleware(): void {
    // Security middleware
    this.app.use((helmet as any)({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"]
        }
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS configuration
    this.app.use((cors as any)({
      origin: config.cors.allowedOrigins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // Rate limiting
    const limiter = (rateLimit as any)({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: config.rateLimit.maxRequests, // Limit each IP to 100 requests per windowMs
      message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use('/api/', limiter);

    // Body parsing middleware
    this.app.use((express as any).json({ limit: '10mb' }));
    this.app.use((express as any).urlencoded({ extended: true, limit: '10mb' }));

    // Compression middleware
    this.app.use((compression as any)());

    // Logging middleware
    if (config.env !== 'test') {
      this.app.use((morgan as any)('combined', {
        stream: {
          write: (message: string) => logger.info(message.trim())
        }
      }));
    }

    // Request validation middleware
    this.app.use(validateRequestSize);

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.env,
        version: process.env['npm_package_version'] || '1.0.0'
      });
    });

    // API status endpoint
    this.app.get('/api/status', (req, res) => {
      res.status(200).json({
        api: 'AugustInsurance Backend API',
        version: '1.0.0',
        status: 'operational',
        timestamp: new Date().toISOString(),
        services: {
          database: 'connected',
          redis: 'connected',
          blockchain: 'connected',
          ml: 'operational'
        }
      });
    });
  }

  private initializeRoutes(): void {
    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/claims', authMiddleware, claimsRoutes);
    this.app.use('/api/providers', authMiddleware, providersRoutes);
    this.app.use('/api/policies', authMiddleware, policiesRoutes);
    this.app.use('/api/settlements', authMiddleware, settlementsRoutes);
    this.app.use('/api/fraud', authMiddleware, fraudRoutes);
    this.app.use('/api/multisig', authMiddleware, multisigRoutes);

    // Catch-all route for undefined endpoints
    this.app.use('/api/*', (req, res) => {
      res.status(404).json({
        error: 'API endpoint not found',
        message: `The endpoint ${req.originalUrl} does not exist`,
        availableEndpoints: [
          '/api/auth',
          '/api/claims',
          '/api/providers',
          '/api/policies',
          '/api/settlements',
          '/api/fraud',
          '/api/multisig'
        ]
      });
    });

    // Root route
    this.app.get('/', (req, res) => {
      res.json({
        message: 'Welcome to AugustInsurance API',
        version: '1.0.0',
        documentation: '/api-docs',
        health: '/health',
        status: '/api/status'
      });
    });
  }

  private initializeSwagger(): void {
    const options = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'AugustInsurance API',
          version: '1.0.0',
          description: 'Professional health insurance claims processing platform API',
          contact: {
            name: 'AugustInsurance Team',
            email: 'api@augustinsurance.com',
            url: 'https://augustinsurance.com'
          },
          license: {
            name: 'MIT',
            url: 'https://opensource.org/licenses/MIT'
          }
        },
        servers: [
          {
            url: config.api.baseUrl,
            description: 'Production server'
          },
          {
            url: 'http://localhost:3000',
            description: 'Development server'
          }
        ],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT'
            }
          }
        },
        security: [
          {
            bearerAuth: []
          }
        ]
      },
      apis: ['./src/routes/*.ts', './src/models/*.ts']
    };

    const specs = (swaggerJsdoc as any)(options);
    this.app.use('/api-docs', (swaggerUi as any).serve, (swaggerUi as any).setup(specs, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'AugustInsurance API Documentation'
    }));
  }

  private initializeErrorHandling(): void {
    // Global error handler
    this.app.use(errorHandler);

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
      logger.error(`Unhandled Rejection at: ${promise} reason: ${reason}`);
      // Close server & exit process
      this.server.close(() => {
        process.exit(1);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received. Shutting down gracefully...');
      this.server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received. Shutting down gracefully...');
      this.server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
      });
    });
  }

  private initializeSocketIO(): void {
    this.io.on('connection', (socket: Socket) => {
      logger.info(`Client connected: ${socket.id}`);

      // Join user-specific room for notifications
      socket.on('join', (data: { userId: string; role: string }) => {
        const { userId, role } = data;
        socket.join(`user_${userId}`);
        socket.join(`role_${role}`);
        logger.info(`User ${userId} joined rooms`);
      });

      // Handle claim status updates
      socket.on('subscribe_claim', (claimId: string) => {
        socket.join(`claim_${claimId}`);
        logger.info(`Client subscribed to claim ${claimId}`);
      });

      // Handle settlement updates
      socket.on('subscribe_settlement', (settlementId: string) => {
        socket.join(`settlement_${settlementId}`);
        logger.info(`Client subscribed to settlement ${settlementId}`);
      });

      socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
      });
    });

    // Make io available globally
    global.io = this.io;
  }

  public async start(): Promise<void> {
    try {
      // Initialize services
      await this.initializeServices();

      // Start server
      this.server.listen(this.port, () => {
        logger.info(`🚀 AugustInsurance API server running on port ${this.port}`);
        logger.info(`📚 API Documentation available at http://localhost:${this.port}/api-docs`);
        logger.info(`🏥 Health check available at http://localhost:${this.port}/health`);
        logger.info(`📊 API status available at http://localhost:${this.port}/api/status`);
        logger.info(`🌍 Environment: ${config.env}`);
      });
    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  private async initializeServices(): Promise<void> {
    try {
      logger.info('Initializing services...');

      // Initialize database
      await databaseService.initialize();
      logger.info('✅ Database service initialized');

      // Initialize Redis
      await redisService.initialize();
      logger.info('✅ Redis service initialized');

      // Initialize blockchain service
      await blockchainService.initialize();
      logger.info('✅ Blockchain service initialized');

      logger.info('🎉 All services initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize services:', error);
      throw error;
    }
  }

  public getApp(): express.Application {
    return this.app;
  }

  public getServer(): any {
    return this.server;
  }

  public getIO(): Server {
    return this.io;
  }
}

// Create and start server
const server = new AugustInsuranceServer();

if (require.main === module) {
  server.start().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default server;
export { AugustInsuranceServer };

// Global type declarations
declare global {
  var io: Server;
}

// Export for testing
export const app = server.getApp();