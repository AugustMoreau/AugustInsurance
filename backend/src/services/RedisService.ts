import type { RedisOptions } from 'ioredis';
import Redis from 'ioredis';
import { config } from '../config';
import logger, { performanceLogger } from '../utils/logger';

interface CacheOptions {
  ttl?: number;
  compress?: boolean;
  serialize?: boolean;
}

interface SessionData {
  userId: string;
  role?: string;
  permissions?: string[];
  lastActivity: number;
  createdAt?: number;
  ipAddress?: string;
  userAgent?: string;
  isActive?: boolean;
}

interface LockOptions {
  ttl?: number;
  retries?: number;
  retryDelay?: number;
}

class RedisService {
  private static instance: RedisService;
  private client: Redis | null = null;
  private subscriber: Redis | null = null;
  private publisher: Redis | null = null;
  private isInitialized = false;

  private constructor() {}

  public static getInstance(): RedisService {
    if (!RedisService.instance) {
      RedisService.instance = new RedisService();
    }
    return RedisService.instance;
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Redis service already initialized');
      return;
    }

    try {
      const redisOptions: RedisOptions = {
        host: config.redis.host,
        port: config.redis.port,
        ...(config.redis.password && { password: config.redis.password }),
        db: config.redis.db,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        keepAlive: 30000,
        connectTimeout: 10000,
        commandTimeout: 5000,
        family: 4,
      };

      // Main client for general operations
      this.client = new Redis(redisOptions);

      // Separate clients for pub/sub
      this.subscriber = new Redis(redisOptions);
      this.publisher = new Redis(redisOptions);

      // Set up event handlers
      this.setupEventHandlers();

      // Connect all clients
      await Promise.all([
        this.client.connect(),
        this.subscriber.connect(),
        this.publisher.connect(),
      ]);

      // Test connection
      await this.client.ping();

      this.isInitialized = true;
      logger.info('Redis service initialized successfully');
    } catch (error) {
      logger.logError(error as Error, 'Redis initialization');
      throw new Error(`Failed to initialize Redis: ${(error as Error).message}`);
    }
  }

  private setupEventHandlers(): void {
    if (!this.client || !this.subscriber || !this.publisher) {
      return;
    }

    // Main client events
    this.client.on('connect', () => {
      logger.debug('Redis client connected');
    });

    this.client.on('ready', () => {
      logger.debug('Redis client ready');
    });

    this.client.on('error', (error) => {
      logger.logError(error, 'Redis client error');
    });

    this.client.on('close', () => {
      logger.warn('Redis client connection closed');
    });

    this.client.on('reconnecting', () => {
      logger.info('Redis client reconnecting');
    });

    // Subscriber events
    this.subscriber.on('error', (error) => {
      logger.logError(error, 'Redis subscriber error');
    });

    // Publisher events
    this.publisher.on('error', (error) => {
      logger.logError(error, 'Redis publisher error');
    });
  }

  // Cache operations
  public async get<T = any>(key: string): Promise<T | null> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const perf = performanceLogger.start(`Redis GET ${key}`);

    try {
      const value = await this.client.get(key);
      perf.end({ hit: value !== null });

      if (value === null) {
        return null;
      }

      try {
        return JSON.parse(value);
      } catch {
        return value as T;
      }
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Redis GET operation', { key });
      throw error;
    }
  }

  public async set(
    key: string,
    value: any,
    options: CacheOptions = {},
  ): Promise<void> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const { ttl = config.cache.ttl, serialize = true } = options;
    const perf = performanceLogger.start(`Redis SET ${key}`);

    try {
      const serializedValue = serialize ? JSON.stringify(value) : value;

      if (ttl > 0) {
        await this.client.setex(key, ttl, serializedValue);
      } else {
        await this.client.set(key, serializedValue);
      }

      perf.end({ ttl });
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Redis SET operation', { key, ttl });
      throw error;
    }
  }

  public async del(key: string | string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const keys = Array.isArray(key) ? key : [key];
    const perf = performanceLogger.start(`Redis DEL ${keys.length} keys`);

    try {
      const result = await this.client.del(...keys);
      perf.end({ deletedCount: result });
      return result;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Redis DEL operation', { keys });
      throw error;
    }
  }

  public async exists(key: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (error) {
      logger.logError(error as Error, 'Redis EXISTS operation', { key });
      throw error;
    }
  }

  public async expire(key: string, ttl: number): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      const result = await this.client.expire(key, ttl);
      return result === 1;
    } catch (error) {
      logger.logError(error as Error, 'Redis EXPIRE operation', { key, ttl });
      throw error;
    }
  }

  public async ttl(key: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.ttl(key);
    } catch (error) {
      logger.logError(error as Error, 'Redis TTL operation', { key });
      throw error;
    }
  }

  // Hash operations
  public async hget(key: string, field: string): Promise<string | null> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.hget(key, field);
    } catch (error) {
      logger.logError(error as Error, 'Redis HGET operation', { key, field });
      throw error;
    }
  }

  public async hset(key: string, field: string, value: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.hset(key, field, value);
    } catch (error) {
      logger.logError(error as Error, 'Redis HSET operation', { key, field });
      throw error;
    }
  }

  public async hgetall(key: string): Promise<Record<string, string>> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.hgetall(key);
    } catch (error) {
      logger.logError(error as Error, 'Redis HGETALL operation', { key });
      throw error;
    }
  }

  public async hdel(key: string, field: string | string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const fields = Array.isArray(field) ? field : [field];

    try {
      return await this.client.hdel(key, ...fields);
    } catch (error) {
      logger.logError(error as Error, 'Redis HDEL operation', { key, fields });
      throw error;
    }
  }

  // List operations
  public async lpush(key: string, ...values: string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.lpush(key, ...values);
    } catch (error) {
      logger.logError(error as Error, 'Redis LPUSH operation', { key });
      throw error;
    }
  }

  public async rpop(key: string): Promise<string | null> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.rpop(key);
    } catch (error) {
      logger.logError(error as Error, 'Redis RPOP operation', { key });
      throw error;
    }
  }

  public async llen(key: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.llen(key);
    } catch (error) {
      logger.logError(error as Error, 'Redis LLEN operation', { key });
      throw error;
    }
  }

  // Set operations
  public async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.sadd(key, ...members);
    } catch (error) {
      logger.logError(error as Error, 'Redis SADD operation', { key });
      throw error;
    }
  }

  public async srem(key: string, ...members: string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.srem(key, ...members);
    } catch (error) {
      logger.logError(error as Error, 'Redis SREM operation', { key });
      throw error;
    }
  }

  public async smembers(key: string): Promise<string[]> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      return await this.client.smembers(key);
    } catch (error) {
      logger.logError(error as Error, 'Redis SMEMBERS operation', { key });
      throw error;
    }
  }

  public async sismember(key: string, member: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    try {
      const result = await this.client.sismember(key, member);
      return result === 1;
    } catch (error) {
      logger.logError(error as Error, 'Redis SISMEMBER operation', { key, member });
      throw error;
    }
  }

  // Session management
  public async createSession(sessionId: string, sessionData: SessionData, ttl: number = 86400): Promise<void> {
    const key = `session:${sessionId}`;
    await this.set(key, sessionData, { ttl });

    // Track user sessions
    const userSessionsKey = `user_sessions:${sessionData.userId}`;
    await this.sadd(userSessionsKey, sessionId);
    await this.expire(userSessionsKey, ttl);

    logger.debug('Session created', { sessionId, userId: sessionData.userId });
  }

  public async getSession(sessionId: string): Promise<SessionData | null> {
    const key = `session:${sessionId}`;
    return this.get<SessionData>(key);
  }

  public async updateSession(sessionId: string, updates: Partial<SessionData>): Promise<void> {
    const key = `session:${sessionId}`;
    const existingSession = await this.get<SessionData>(key);

    if (!existingSession) {
      throw new Error('Session not found');
    }

    const updatedSession = { ...existingSession, ...updates, lastActivity: Date.now() };
    const ttl = await this.ttl(key);

    await this.set(key, updatedSession, { ttl: ttl > 0 ? ttl : config.cache.ttl });
  }

  public async deleteSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);

    if (session) {
      // Remove from user sessions set
      const userSessionsKey = `user_sessions:${session.userId}`;
      await this.srem(userSessionsKey, sessionId);
    }

    const key = `session:${sessionId}`;
    await this.del(key);

    logger.debug('Session deleted', { sessionId });
  }

  public async getUserSessions(userId: string): Promise<string[]> {
    const key = `user_sessions:${userId}`;
    return this.smembers(key);
  }

  public async deleteUserSessions(userId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);

    if (sessions.length > 0) {
      const sessionKeys = sessions.map(sessionId => `session:${sessionId}`);
      await this.del(sessionKeys);
      await this.del(`user_sessions:${userId}`);
    }

    logger.debug('All user sessions deleted', { userId, sessionCount: sessions.length });
  }

  // Distributed locking
  public async acquireLock(
    lockKey: string,
    lockValue: string,
    options: LockOptions = {},
  ): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const { ttl = 30, retries = 3, retryDelay = 100 } = options;
    const key = `lock:${lockKey}`;

    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const result = await this.client.set(key, lockValue, 'PX', ttl * 1000, 'NX');

        if (result === 'OK') {
          logger.debug('Lock acquired', { lockKey, lockValue, ttl });
          return true;
        }

        if (attempt < retries - 1) {
          await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
        }
      } catch (error) {
        logger.logError(error as Error, 'Lock acquisition failed', { lockKey, attempt });

        if (attempt === retries - 1) {
          throw error;
        }
      }
    }

    return false;
  }

  public async releaseLock(lockKey: string, lockValue: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    const key = `lock:${lockKey}`;

    // Lua script to ensure we only delete the lock if we own it
    const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      else
        return 0
      end
    `;

    try {
      const result = await this.client.eval(script, 1, key, lockValue) as number;
      const released = result === 1;

      if (released) {
        logger.debug('Lock released', { lockKey, lockValue });
      }

      return released;
    } catch (error) {
      logger.logError(error as Error, 'Lock release failed', { lockKey });
      throw error;
    }
  }

  // Pub/Sub operations
  public async publish(channel: string, message: any): Promise<number> {
    if (!this.publisher) {
      throw new Error('Redis publisher not initialized');
    }

    try {
      const serializedMessage = typeof message === 'string' ? message : JSON.stringify(message);
      const result = await this.publisher.publish(channel, serializedMessage);

      logger.debug('Message published', { channel, subscriberCount: result });
      return result;
    } catch (error) {
      logger.logError(error as Error, 'Redis publish failed', { channel });
      throw error;
    }
  }

  public async subscribe(channel: string, callback: (message: string) => void): Promise<void> {
    if (!this.subscriber) {
      throw new Error('Redis subscriber not initialized');
    }

    try {
      await this.subscriber.subscribe(channel);

      this.subscriber.on('message', (receivedChannel, message) => {
        if (receivedChannel === channel) {
          callback(message);
        }
      });

      logger.debug('Subscribed to channel', { channel });
    } catch (error) {
      logger.logError(error as Error, 'Redis subscribe failed', { channel });
      throw error;
    }
  }

  public async unsubscribe(channel: string): Promise<void> {
    if (!this.subscriber) {
      throw new Error('Redis subscriber not initialized');
    }

    try {
      await this.subscriber.unsubscribe(channel);
      logger.debug('Unsubscribed from channel', { channel });
    } catch (error) {
      logger.logError(error as Error, 'Redis unsubscribe failed', { channel });
      throw error;
    }
  }

  // Health check
  public async healthCheck(): Promise<{ status: string; latency: number }> {
    const startTime = Date.now();

    try {
      if (!this.client) {
        throw new Error('Redis not initialized');
      }

      await this.client.ping();
      const latency = Date.now() - startTime;

      return {
        status: 'healthy',
        latency,
      };
    } catch (error) {
      logger.logError(error as Error, 'Redis health check failed');
      return {
        status: 'unhealthy',
        latency: Date.now() - startTime,
      };
    }
  }

  // Cleanup and shutdown
  public async close(): Promise<void> {
    try {
      if (this.client) {
        await this.client.quit();
        this.client = null;
      }

      if (this.subscriber) {
        await this.subscriber.quit();
        this.subscriber = null;
      }

      if (this.publisher) {
        await this.publisher.quit();
        this.publisher = null;
      }

      this.isInitialized = false;
      logger.info('Redis service closed');
    } catch (error) {
      logger.logError(error as Error, 'Redis service shutdown');
      throw error;
    }
  }

  public isReady(): boolean {
    return this.isInitialized &&
           this.client !== null &&
           this.subscriber !== null &&
           this.publisher !== null;
  }

  public getClient(): Redis | null {
    return this.client;
  }
}

// Export singleton instance
const redisService = RedisService.getInstance();
export default redisService;
export { RedisService, SessionData };