import type { PoolClient, QueryResult, QueryResultRow } from 'pg';
import { Pool } from 'pg';
import { config } from '../config';
import logger, { queryLogger, performanceLogger } from '../utils/logger';

// Database service using singleton pattern - probably overkill but whatever

interface QueryOptions {
  timeout?: number;
  retries?: number;
  logQuery?: boolean;
}

interface TransactionCallback<T> {
  (client: PoolClient): Promise<T>;
}

class DatabaseService {
  private static instance: DatabaseService;
  private pool: Pool | null = null;
  private isInitialized = false;

  private constructor() {}

  public static getInstance(): DatabaseService {
    if (!DatabaseService.instance) {
      DatabaseService.instance = new DatabaseService();
    }
    return DatabaseService.instance;
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Database service already initialized');
      return;
    }

    try {
      // Pool configuration - these timeouts might need tweaking
      const poolConfig = {
        host: config.database.host,
        port: config.database.port,
        database: config.database.name,
        user: config.database.user,
        password: config.database.password,
        ssl: config.database.ssl ? { rejectUnauthorized: false } : false, // TODO: proper SSL in prod
        min: config.database.pool.min,
        max: config.database.pool.max,
        idleTimeoutMillis: 30000, // 30 seconds
        connectionTimeoutMillis: 10000, // 10 seconds - might be too short?
        statement_timeout: 30000,
        query_timeout: 30000,
      };

      this.pool = new Pool(poolConfig);

      // Test connection
      const client = await this.pool.connect();
      await client.query('SELECT NOW()');
      client.release();

      // Set up event handlers
      this.setupEventHandlers();

      // Initialize database schema
      await this.initializeSchema();

      this.isInitialized = true;
      logger.info('Database service initialized successfully');
    } catch (error) {
      logger.logError(error as Error, 'Database initialization');
      throw new Error(`Failed to initialize database: ${(error as Error).message}`);
    }
  }

  private setupEventHandlers(): void {
    if (!this.pool) {
      return;
    }

    this.pool.on('connect', (client) => {
      logger.debug('New database client connected');
    });

    this.pool.on('acquire', (client) => {
      logger.debug('Database client acquired from pool');
    });

    this.pool.on('remove', (client) => {
      logger.debug('Database client removed from pool');
    });

    this.pool.on('error', (err, client) => {
      logger.logError(err, 'Database pool error');
    });
  }

  private async initializeSchema(): Promise<void> {
    const perf = performanceLogger.start('Database schema initialization');

    try {
      // Create extensions
      await this.query(`
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        CREATE EXTENSION IF NOT EXISTS "pg_trgm";
      `);

      // Create enums
      await this.createEnums();

      // Create tables
      await this.createTables();

      // Create indexes
      await this.createIndexes();

      // Create functions and triggers
      await this.createFunctionsAndTriggers();

      logger.info('Database schema initialized successfully');
    } catch (error) {
      logger.logError(error as Error, 'Database schema initialization');
      throw error;
    } finally {
      perf.end();
    }
  }

  private async createEnums(): Promise<void> {
    const enums = [
      {
        name: 'user_role',
        values: ['admin', 'claims_processor', 'medical_director', 'financial_controller', 'fraud_analyst', 'provider', 'patient', 'auditor'],
      },
      {
        name: 'claim_status',
        values: ['submitted', 'under_review', 'approved', 'rejected', 'settled', 'disputed'],
      },
      {
        name: 'claim_priority',
        values: ['low', 'normal', 'high', 'urgent', 'emergency'],
      },
      {
        name: 'settlement_status',
        values: ['pending', 'processing', 'completed', 'failed', 'disputed'],
      },
      {
        name: 'fraud_risk_level',
        values: ['low', 'medium', 'high', 'critical'],
      },
      {
        name: 'approval_status',
        values: ['pending', 'approved', 'rejected', 'expired'],
      },
      {
        name: 'notification_type',
        values: ['email', 'sms', 'push', 'in_app'],
      },
      {
        name: 'audit_action',
        values: ['create', 'read', 'update', 'delete', 'approve', 'reject', 'settle'],
      },
    ];

    for (const enumDef of enums) {
      try {
        const enumValues = enumDef.values.map(v => `'${v}'`).join(', ');
        await this.query(`CREATE TYPE ${enumDef.name} AS ENUM (${enumValues})`);
      } catch (error: any) {
        // Ignore error if type already exists
        if (!error.message.includes('already exists')) {
          throw error;
        }
      }
    }
  }

  private async createTables(): Promise<void> {
    // Users table
    await this.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        role user_role NOT NULL,
        phone VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        email_verified BOOLEAN DEFAULT false,
        last_login TIMESTAMP WITH TIME ZONE,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Providers table
    await this.query(`
      CREATE TABLE IF NOT EXISTS providers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        license_number VARCHAR(100) UNIQUE NOT NULL,
        specialty VARCHAR(100),
        address JSONB,
        contact_info JSONB,
        verification_status VARCHAR(50) DEFAULT 'pending',
        risk_score DECIMAL(3,2) DEFAULT 0.00,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Policies table
    await this.query(`
      CREATE TABLE IF NOT EXISTS policies (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        policy_number VARCHAR(100) UNIQUE NOT NULL,
        holder_id UUID REFERENCES users(id),
        coverage_details JSONB NOT NULL,
        premium_amount DECIMAL(10,2) NOT NULL,
        deductible DECIMAL(10,2) NOT NULL,
        coverage_limits JSONB,
        effective_date DATE NOT NULL,
        expiry_date DATE NOT NULL,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Claims table
    await this.query(`
      CREATE TABLE IF NOT EXISTS claims (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        claim_number VARCHAR(100) UNIQUE NOT NULL,
        policy_id UUID REFERENCES policies(id) NOT NULL,
        provider_id UUID REFERENCES providers(id) NOT NULL,
        patient_id UUID REFERENCES users(id) NOT NULL,
        claim_amount DECIMAL(12,2) NOT NULL,
        diagnosis_codes TEXT[],
        procedure_codes TEXT[],
        service_date DATE NOT NULL,
        submission_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        status claim_status DEFAULT 'submitted',
        priority claim_priority DEFAULT 'normal',
        fraud_score DECIMAL(3,2) DEFAULT 0.00,
        fraud_flags TEXT[],
        auto_approved BOOLEAN DEFAULT false,
        requires_review BOOLEAN DEFAULT true,
        settlement_amount DECIMAL(12,2),
        settlement_date TIMESTAMP WITH TIME ZONE,
        blockchain_tx_hash VARCHAR(66),
        documents JSONB DEFAULT '[]',
        notes TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Settlements table
    await this.query(`
      CREATE TABLE IF NOT EXISTS settlements (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        claim_id UUID REFERENCES claims(id) NOT NULL,
        provider_id UUID REFERENCES providers(id) NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        currency VARCHAR(3) DEFAULT 'USD',
        status settlement_status DEFAULT 'pending',
        payment_method VARCHAR(50),
        transaction_id VARCHAR(255),
        blockchain_tx_hash VARCHAR(66),
        processing_fee DECIMAL(8,2) DEFAULT 0.00,
        net_amount DECIMAL(12,2),
        scheduled_date TIMESTAMP WITH TIME ZONE,
        processed_date TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Fraud analysis table
    await this.query(`
      CREATE TABLE IF NOT EXISTS fraud_analysis (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        claim_id UUID REFERENCES claims(id) NOT NULL,
        risk_level fraud_risk_level NOT NULL,
        fraud_score DECIMAL(3,2) NOT NULL,
        patterns_detected TEXT[],
        ml_model_version VARCHAR(50),
        analysis_details JSONB,
        reviewed_by UUID REFERENCES users(id),
        review_notes TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Multi-signature approvals table
    await this.query(`
      CREATE TABLE IF NOT EXISTS multi_sig_approvals (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        claim_id UUID REFERENCES claims(id) NOT NULL,
        required_approvers INTEGER NOT NULL,
        current_approvals INTEGER DEFAULT 0,
        status approval_status DEFAULT 'pending',
        approvers JSONB DEFAULT '[]',
        approval_threshold DECIMAL(12,2),
        emergency_override BOOLEAN DEFAULT false,
        expires_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Approval votes table
    await this.query(`
      CREATE TABLE IF NOT EXISTS approval_votes (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        approval_id UUID REFERENCES multi_sig_approvals(id) NOT NULL,
        approver_id UUID REFERENCES users(id) NOT NULL,
        vote BOOLEAN NOT NULL,
        comments TEXT,
        voted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(approval_id, approver_id)
      )
    `);

    // Audit logs table
    await this.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id),
        action audit_action NOT NULL,
        resource_type VARCHAR(50) NOT NULL,
        resource_id UUID,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Notifications table
    await this.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) NOT NULL,
        type notification_type NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        data JSONB,
        read BOOLEAN DEFAULT false,
        sent BOOLEAN DEFAULT false,
        sent_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Sessions table
    await this.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) NOT NULL,
        token_hash VARCHAR(255) NOT NULL,
        refresh_token_hash VARCHAR(255),
        ip_address INET,
        user_agent TEXT,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
  }

  private async createIndexes(): Promise<void> {
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)',
      'CREATE INDEX IF NOT EXISTS idx_providers_license ON providers(license_number)',
      'CREATE INDEX IF NOT EXISTS idx_policies_number ON policies(policy_number)',
      'CREATE INDEX IF NOT EXISTS idx_policies_holder ON policies(holder_id)',
      'CREATE INDEX IF NOT EXISTS idx_claims_number ON claims(claim_number)',
      'CREATE INDEX IF NOT EXISTS idx_claims_policy ON claims(policy_id)',
      'CREATE INDEX IF NOT EXISTS idx_claims_provider ON claims(provider_id)',
      'CREATE INDEX IF NOT EXISTS idx_claims_patient ON claims(patient_id)',
      'CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status)',
      'CREATE INDEX IF NOT EXISTS idx_claims_submission_date ON claims(submission_date)',
      'CREATE INDEX IF NOT EXISTS idx_claims_fraud_score ON claims(fraud_score)',
      'CREATE INDEX IF NOT EXISTS idx_settlements_claim ON settlements(claim_id)',
      'CREATE INDEX IF NOT EXISTS idx_settlements_provider ON settlements(provider_id)',
      'CREATE INDEX IF NOT EXISTS idx_settlements_status ON settlements(status)',
      'CREATE INDEX IF NOT EXISTS idx_fraud_analysis_claim ON fraud_analysis(claim_id)',
      'CREATE INDEX IF NOT EXISTS idx_fraud_analysis_risk_level ON fraud_analysis(risk_level)',
      'CREATE INDEX IF NOT EXISTS idx_multi_sig_claim ON multi_sig_approvals(claim_id)',
      'CREATE INDEX IF NOT EXISTS idx_multi_sig_status ON multi_sig_approvals(status)',
      'CREATE INDEX IF NOT EXISTS idx_approval_votes_approval ON approval_votes(approval_id)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)',
      'CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)',
    ];

    for (const indexSql of indexes) {
      await this.query(indexSql);
    }
  }

  private async createFunctionsAndTriggers(): Promise<void> {
    // Updated timestamp trigger function
    await this.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Create triggers for updated_at
    const tables = ['users', 'providers', 'policies', 'claims', 'settlements', 'fraud_analysis', 'multi_sig_approvals'];
    for (const table of tables) {
      await this.query(`
        DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table};
        CREATE TRIGGER update_${table}_updated_at
          BEFORE UPDATE ON ${table}
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
      `);
    }

    // Audit trigger function
    await this.query(`
      CREATE OR REPLACE FUNCTION audit_trigger_function()
      RETURNS TRIGGER AS $$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          INSERT INTO audit_logs (action, resource_type, resource_id, new_values)
          VALUES ('create', TG_TABLE_NAME, NEW.id, row_to_json(NEW));
          RETURN NEW;
        ELSIF TG_OP = 'UPDATE' THEN
          INSERT INTO audit_logs (action, resource_type, resource_id, old_values, new_values)
          VALUES ('update', TG_TABLE_NAME, NEW.id, row_to_json(OLD), row_to_json(NEW));
          RETURN NEW;
        ELSIF TG_OP = 'DELETE' THEN
          INSERT INTO audit_logs (action, resource_type, resource_id, old_values)
          VALUES ('delete', TG_TABLE_NAME, OLD.id, row_to_json(OLD));
          RETURN OLD;
        END IF;
        RETURN NULL;
      END;
      $$ language 'plpgsql';
    `);
  }

  public async query<T extends QueryResultRow = any>(
    text: string,
    params?: any[],
    options: QueryOptions = {},
  ): Promise<QueryResult<T>> {
    if (!this.pool) {
      throw new Error('Database not initialized');
    }

    const { timeout = 30000, retries = 3, logQuery = true } = options;
    const startTime = Date.now();

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const result: any = await this.pool.query({
          text,
          values: params || [],

        });

        if (logQuery) {
          queryLogger.log(text, startTime, result.rowCount || 0);
        }

        return result;
      } catch (error) {
        const isLastAttempt = attempt === retries;
        const shouldRetry = this.shouldRetryQuery(error as Error);

        if (isLastAttempt || !shouldRetry) {
          logger.logError(error as Error, 'Database query', {
            query: text.substring(0, 200),
            params: params?.slice(0, 5),
            attempt,
            duration: Date.now() - startTime,
          });
          throw error;
        }

        logger.warn(`Database query failed, retrying (${attempt}/${retries})`, {
          error: (error as Error).message,
          query: text.substring(0, 100),
        });

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, attempt * 1000));
      }
    }

    throw new Error('Query failed after all retries');
  }

  public async transaction<T>(callback: TransactionCallback<T>): Promise<T> {
    if (!this.pool) {
      throw new Error('Database not initialized');
    }

    const client = await this.pool.connect();
    const perf = performanceLogger.start('Database transaction');

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');

      perf.end({ status: 'committed' });
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      perf.end({ status: 'rolled_back', error: (error as Error).message });
      logger.logError(error as Error, 'Database transaction');
      throw error;
    } finally {
      client.release();
    }
  }

  private shouldRetryQuery(error: Error): boolean {
    const retryableErrors = [
      'connection terminated',
      'connection reset',
      'timeout',
      'ECONNRESET',
      'ENOTFOUND',
      'ETIMEDOUT',
    ];

    return retryableErrors.some(retryableError =>
      error.message.toLowerCase().includes(retryableError),
    );
  }

  public async healthCheck(): Promise<{ status: string; latency: number }> {
    const startTime = Date.now();

    try {
      await this.query('SELECT 1', [], { logQuery: false });
      const latency = Date.now() - startTime;

      return {
        status: 'healthy',
        latency,
      };
    } catch (error) {
      logger.logError(error as Error, 'Database health check');
      return {
        status: 'unhealthy',
        latency: Date.now() - startTime,
      };
    }
  }

  public async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.isInitialized = false;
      logger.info('Database connection closed');
    }
  }

  public getPool(): Pool | null {
    return this.pool;
  }

  public isReady(): boolean {
    return this.isInitialized && this.pool !== null;
  }
}

// Export singleton instance
const databaseService = DatabaseService.getInstance();
export default databaseService;
export { DatabaseService };