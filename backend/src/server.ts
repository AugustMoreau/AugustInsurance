import 'dotenv/config';
import App from './app';
import { config } from './config';
import logger from './utils/logger';

// Validate environment configuration
if (config.env === 'production') {
  // Production specific checks can be added here if needed
}

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', {
    error: error.message,
    stack: error.stack,
    name: error.name
  });
  
  // Exit gracefully
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logger.error('Unhandled Rejection', {
    reason: reason?.message || reason,
    stack: reason?.stack,
    promise: promise.toString()
  });
  
  // Exit gracefully
  process.exit(1);
});

// Handle process warnings
process.on('warning', (warning) => {
  logger.warn('Process Warning', {
    name: warning.name,
    message: warning.message,
    stack: warning.stack
  });
});

// Log startup information
logger.info('Starting Augustium Health Insurance Claims API', {
  nodeVersion: process.version,
  platform: process.platform,
  architecture: process.arch,
  environment: config.env,
  pid: process.pid,
  memory: process.memoryUsage(),
  uptime: process.uptime()
});

// Create and start the application
const app = new App();

app.start().catch((error) => {
  logger.error('Failed to start application', {
    error: error.message,
    stack: error.stack
  });
  process.exit(1);
});

// Export for testing
export default app;