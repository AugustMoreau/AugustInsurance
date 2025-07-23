import { ethers } from 'ethers';
import { config } from '../config';
import logger, { performanceLogger } from '../utils/logger';

// Smart contract ABIs (simplified for demonstration)
const CLAIMS_PROCESSOR_ABI = [
  'function submitClaim(string memory claimId, uint256 amount, string memory diagnosis, string memory procedure, address provider, address patient) external returns (bool)',
  'function reviewClaim(string memory claimId, bool approved, uint256 settlementAmount) external returns (bool)',
  'function getClaim(string memory claimId) external view returns (tuple(string id, uint256 amount, uint8 status, address provider, address patient, uint256 timestamp))',
  'function settleClaim(string memory claimId) external returns (bool)',
  'event ClaimSubmitted(string indexed claimId, uint256 amount, address indexed provider, address indexed patient)',
  'event ClaimReviewed(string indexed claimId, bool approved, uint256 settlementAmount)',
  'event ClaimSettled(string indexed claimId, uint256 amount, address indexed provider)',
];

const FRAUD_DETECTOR_ABI = [
  'function analyzeClaim(string memory claimId, uint256 amount, address provider, address patient, string memory patterns) external returns (uint256)',
  'function getFraudScore(string memory claimId) external view returns (uint256)',
  'function updateMLModel(string memory modelHash, string memory version) external returns (bool)',
  'function flagProvider(address provider, bool flagged) external returns (bool)',
  'event FraudAnalysisCompleted(string indexed claimId, uint256 fraudScore, string patterns)',
  'event ProviderFlagged(address indexed provider, bool flagged)',
];

const MULTISIG_APPROVAL_ABI = [
  'function createApprovalRequest(string memory claimId, uint256 amount, uint8 requiredApprovers) external returns (string memory)',
  'function submitApproval(string memory requestId, bool approved, string memory comments) external returns (bool)',
  'function getApprovalStatus(string memory requestId) external view returns (tuple(uint8 currentApprovals, uint8 requiredApprovers, bool completed, bool approved))',
  'function emergencyOverride(string memory requestId, string memory reason) external returns (bool)',
  'event ApprovalRequestCreated(string indexed requestId, string indexed claimId, uint256 amount)',
  'event ApprovalSubmitted(string indexed requestId, address indexed approver, bool approved)',
  'event ApprovalCompleted(string indexed requestId, bool approved)',
  'event EmergencyOverride(string indexed requestId, address indexed overrider, string reason)',
];

const SETTLEMENT_ENGINE_ABI = [
  'function initiateSettlement(string memory settlementId, address provider, uint256 amount, string memory currency) external returns (bool)',
  'function processSettlement(string memory settlementId) external returns (bool)',
  'function getSettlementStatus(string memory settlementId) external view returns (tuple(uint8 status, uint256 amount, address provider, uint256 timestamp))',
  'function addLiquidity(uint256 amount) external returns (bool)',
  'function withdrawLiquidity(uint256 amount) external returns (bool)',
  'event SettlementInitiated(string indexed settlementId, address indexed provider, uint256 amount)',
  'event SettlementProcessed(string indexed settlementId, address indexed provider, uint256 amount)',
  'event LiquidityAdded(address indexed provider, uint256 amount)',
  'event LiquidityWithdrawn(address indexed provider, uint256 amount)',
];

interface ClaimData {
  id: string;
  amount: string;
  status: number;
  provider: string;
  patient: string;
  timestamp: string;
}

interface ApprovalStatus {
  currentApprovals: number;
  requiredApprovers: number;
  completed: boolean;
  approved: boolean;
}

interface SettlementStatus {
  status: number;
  amount: string;
  provider: string;
  timestamp: string;
}

interface TransactionOptions {
  gasLimit?: number;
  gasPrice?: string;
  value?: string;
  timeout?: number;
}

class BlockchainService {
  private static instance: BlockchainService;
  private provider: ethers.JsonRpcProvider | null = null;
  private wallet: ethers.Wallet | null = null;
  private claimsProcessor: ethers.Contract | null = null;
  private fraudDetector: ethers.Contract | null = null;
  private multiSigApproval: ethers.Contract | null = null;
  private settlementEngine: ethers.Contract | null = null;
  private isInitialized = false;

  private constructor() {}

  public static getInstance(): BlockchainService {
    if (!BlockchainService.instance) {
      BlockchainService.instance = new BlockchainService();
    }
    return BlockchainService.instance;
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Blockchain service already initialized');
      return;
    }

    try {
      // Initialize provider
      this.provider = new ethers.JsonRpcProvider(config.blockchain.rpcUrl);

      // Test connection
      const network = await this.provider.getNetwork();
      logger.info(`Connected to blockchain network: ${network.name} (${network.chainId})`);

      // Initialize wallet
      this.wallet = new ethers.Wallet(config.blockchain.privateKey, this.provider);

      // Get wallet balance
      const balance = await this.provider.getBalance(this.wallet.address);
      logger.info(`Wallet address: ${this.wallet.address}, Balance: ${ethers.formatEther(balance)} ETH`);

      // Initialize smart contracts
      await this.initializeContracts();

      // Set up event listeners
      this.setupEventListeners();

      this.isInitialized = true;
      logger.info('Blockchain service initialized successfully');
    } catch (error) {
      logger.logError(error as Error, 'Blockchain initialization');
      throw new Error(`Failed to initialize blockchain: ${(error as Error).message}`);
    }
  }

  private async initializeContracts(): Promise<void> {
    if (!this.wallet) {
      throw new Error('Wallet not initialized');
    }

    // For demonstration, using the same contract address for all contracts
    // In production, each contract would have its own address
    const { contractAddress } = config.blockchain;

    this.claimsProcessor = new ethers.Contract(contractAddress, CLAIMS_PROCESSOR_ABI, this.wallet);
    this.fraudDetector = new ethers.Contract(contractAddress, FRAUD_DETECTOR_ABI, this.wallet);
    this.multiSigApproval = new ethers.Contract(contractAddress, MULTISIG_APPROVAL_ABI, this.wallet);
    this.settlementEngine = new ethers.Contract(contractAddress, SETTLEMENT_ENGINE_ABI, this.wallet);

    logger.info('Smart contracts initialized');
  }

  private setupEventListeners(): void {
    if (!this.claimsProcessor || !this.fraudDetector || !this.multiSigApproval || !this.settlementEngine) {
      return;
    }

    // Claims Processor events
    this.claimsProcessor.on('ClaimSubmitted', (claimId, amount, provider, patient, event) => {
      logger.logBlockchainTransaction(event.transactionHash, 'ClaimSubmitted', event.gasUsed, {
        claimId,
        amount: ethers.formatEther(amount),
        provider,
        patient,
      });

      // Emit to real-time clients
      if (global.io) {
        global.io.to(`claim_${claimId}`).emit('claimSubmitted', {
          claimId,
          amount: ethers.formatEther(amount),
          provider,
          patient,
          txHash: event.transactionHash,
        });
      }
    });

    this.claimsProcessor.on('ClaimReviewed', (claimId, approved, settlementAmount, event) => {
      logger.logBlockchainTransaction(event.transactionHash, 'ClaimReviewed', event.gasUsed, {
        claimId,
        approved,
        settlementAmount: ethers.formatEther(settlementAmount),
      });

      if (global.io) {
        global.io.to(`claim_${claimId}`).emit('claimReviewed', {
          claimId,
          approved,
          settlementAmount: ethers.formatEther(settlementAmount),
          txHash: event.transactionHash,
        });
      }
    });

    this.claimsProcessor.on('ClaimSettled', (claimId, amount, provider, event) => {
      logger.logBlockchainTransaction(event.transactionHash, 'ClaimSettled', event.gasUsed, {
        claimId,
        amount: ethers.formatEther(amount),
        provider,
      });

      if (global.io) {
        global.io.to(`claim_${claimId}`).emit('claimSettled', {
          claimId,
          amount: ethers.formatEther(amount),
          provider,
          txHash: event.transactionHash,
        });
      }
    });

    // Fraud Detector events
    this.fraudDetector.on('FraudAnalysisCompleted', (claimId, fraudScore, patterns, event) => {
      logger.logFraudDetection(claimId, Number(fraudScore) / 100, patterns.split(','), {
        txHash: event.transactionHash,
      });

      if (global.io) {
        global.io.to(`claim_${claimId}`).emit('fraudAnalysisCompleted', {
          claimId,
          fraudScore: Number(fraudScore) / 100,
          patterns: patterns.split(','),
          txHash: event.transactionHash,
        });
      }
    });

    // Multi-sig Approval events
    this.multiSigApproval.on('ApprovalRequestCreated', (requestId, claimId, amount, event) => {
      logger.logBlockchainTransaction(event.transactionHash, 'ApprovalRequestCreated', event.gasUsed, {
        requestId,
        claimId,
        amount: ethers.formatEther(amount),
      });

      if (global.io) {
        global.io.to('role_medical_director').to('role_financial_controller').emit('approvalRequestCreated', {
          requestId,
          claimId,
          amount: ethers.formatEther(amount),
          txHash: event.transactionHash,
        });
      }
    });

    this.multiSigApproval.on('ApprovalSubmitted', (requestId, approver, approved, event) => {
      logger.logBlockchainTransaction(event.transactionHash, 'ApprovalSubmitted', event.gasUsed, {
        requestId,
        approver,
        approved,
      });

      if (global.io) {
        global.io.to('role_medical_director').to('role_financial_controller').emit('approvalSubmitted', {
          requestId,
          approver,
          approved,
          txHash: event.transactionHash,
        });
      }
    });

    // Settlement Engine events
    this.settlementEngine.on('SettlementProcessed', (settlementId, provider, amount, event) => {
      logger.logSettlement(settlementId, Number(ethers.formatEther(amount)), provider, 'completed', {
        txHash: event.transactionHash,
      });

      if (global.io) {
        global.io.to(`settlement_${settlementId}`).emit('settlementProcessed', {
          settlementId,
          provider,
          amount: ethers.formatEther(amount),
          txHash: event.transactionHash,
        });
      }
    });
  }

  // Claims Processor methods
  public async submitClaim(
    claimId: string,
    amount: string,
    provider: string,
    patient: string,
    options: TransactionOptions = {},
  ): Promise<string> {
    if (!this.claimsProcessor) {
      throw new Error('Claims processor contract not initialized');
    }
    const { claimsProcessor } = this;

    const perf = performanceLogger.start('Blockchain submitClaim');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (claimsProcessor as any).submitClaim(
        claimId,
        amountWei,
        provider,
        patient,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'submitClaim', Number(receipt.gasUsed), {
        claimId,
        amount,
        provider,
        patient,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain submitClaim', { claimId });
      throw error;
    }
  }

  public async reviewClaim(
    claimId: string,
    approved: boolean,
    settlementAmount: string,
    options: TransactionOptions = {},
  ): Promise<string> {
    if (!this.claimsProcessor) {
      throw new Error('Claims processor contract not initialized');
    }
    const { claimsProcessor } = this;

    const perf = performanceLogger.start('Blockchain reviewClaim');

    try {
      const settlementAmountWei = ethers.parseEther(settlementAmount);

      const tx = await (claimsProcessor as any).reviewClaim(
        claimId,
        approved,
        settlementAmountWei,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'reviewClaim', Number(receipt.gasUsed), {
        claimId,
        approved,
        settlementAmount,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain reviewClaim', { claimId });
      throw error;
    }
  }

  public async getClaim(claimId: string): Promise<ClaimData> {
    if (!this.claimsProcessor) {
      throw new Error('Claims processor contract not initialized');
    }
    const { claimsProcessor } = this;

    try {
      const claim = await (claimsProcessor as any).getClaim(claimId);

      return {
        id: claim.id,
        amount: ethers.formatEther(claim.amount),
        status: Number(claim.status),
        provider: claim.provider,
        patient: claim.patient,
        timestamp: claim.timestamp.toString(),
      };
    } catch (error) {
      logger.logError(error as Error, 'Blockchain getClaim', { claimId });
      throw error;
    }
  }

  public async settleClaim(claimId: string, options: TransactionOptions = {}): Promise<string> {
    if (!this.claimsProcessor) {
      throw new Error('Claims processor contract not initialized');
    }
    const { claimsProcessor } = this;

    const perf = performanceLogger.start('Blockchain settleClaim');

    try {
      const tx = await (claimsProcessor as any).settleClaim(claimId, {
        gasLimit: options.gasLimit || config.blockchain.gasLimit,
        gasPrice: options.gasPrice || config.blockchain.gasPrice,
      });

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'settleClaim', Number(receipt.gasUsed), {
        claimId,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain settleClaim', { claimId });
      throw error;
    }
  }

  // Fraud Detector methods
  public async analyzeClaim(
    claimId: string,
    amount: string,
    provider: string,
    patient: string,
    patterns: string,
    options: TransactionOptions = {},
  ): Promise<{ txHash: string; fraudScore: number }> {
    if (!this.fraudDetector) {
      throw new Error('Fraud detector contract not initialized');
    }
    const { fraudDetector } = this;

    const perf = performanceLogger.start('Blockchain analyzeClaim');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (fraudDetector as any).analyzeClaim(
        claimId,
        amountWei,
        provider,
        patient,
        patterns,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();

      // Get fraud score from the transaction logs
      const fraudScore = await this.getFraudScore(claimId);

      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString(), fraudScore });

      logger.logBlockchainTransaction(receipt.hash, 'analyzeClaim', Number(receipt.gasUsed), {
        claimId,
        fraudScore,
      });

      return {
        txHash: receipt.hash,
        fraudScore,
      };
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain analyzeClaim', { claimId });
      throw error;
    }
  }

  public async getFraudScore(claimId: string): Promise<number> {
    if (!this.fraudDetector) {
      throw new Error('Fraud detector contract not initialized');
    }
    const { fraudDetector } = this;

    try {
      const score = await (fraudDetector as any).getFraudScore(claimId);
      return Number(score) / 100; // Convert from basis points to decimal
    } catch (error) {
      logger.logError(error as Error, 'Blockchain getFraudScore', { claimId });
      throw error;
    }
  }

  // Multi-sig Approval methods
  public async createApprovalRequest(
    claimId: string,
    amount: string,
    requiredApprovers: number,
    options: TransactionOptions = {},
  ): Promise<{ txHash: string; requestId: string }> {
    if (!this.multiSigApproval) {
      throw new Error('Multi-sig approval contract not initialized');
    }
    const { multiSigApproval } = this;

    const perf = performanceLogger.start('Blockchain createApprovalRequest');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (multiSigApproval as any).createApprovalRequest(
        claimId,
        amountWei,
        requiredApprovers,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();

      // Extract request ID from transaction logs
      const requestId = `${claimId}_${Date.now()}`; // Simplified for demo

      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString(), requestId });

      logger.logBlockchainTransaction(receipt.hash, 'createApprovalRequest', Number(receipt.gasUsed), {
        claimId,
        requestId,
        requiredApprovers,
      });

      return {
        txHash: receipt.hash,
        requestId,
      };
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain createApprovalRequest', { claimId });
      throw error;
    }
  }

  public async submitApproval(
    requestId: string,
    approved: boolean,
    comments: string,
    options: TransactionOptions = {},
  ): Promise<string> {
    if (!this.multiSigApproval) {
      throw new Error('Multi-sig approval contract not initialized');
    }
    const { multiSigApproval } = this;

    const perf = performanceLogger.start('Blockchain submitApproval');

    try {
      const tx = await (multiSigApproval as any).submitApproval(
        requestId,
        approved,
        comments,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'submitApproval', Number(receipt.gasUsed), {
        requestId,
        approved,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain submitApproval', { requestId });
      throw error;
    }
  }

  public async getApprovalStatus(requestId: string): Promise<ApprovalStatus> {
    if (!this.multiSigApproval) {
      throw new Error('Multi-sig approval contract not initialized');
    }
    const { multiSigApproval } = this;

    try {
      const status = await (multiSigApproval as any).getApprovalStatus(requestId);

      return {
        currentApprovals: Number(status.currentApprovals),
        requiredApprovers: Number(status.requiredApprovers),
        completed: status.completed,
        approved: status.approved,
      };
    } catch (error) {
      logger.logError(error as Error, 'Blockchain getApprovalStatus', { requestId });
      throw error;
    }
  }

  // Settlement Engine methods
  public async initiateSettlement(
    settlementId: string,
    provider: string,
    amount: string,
    currency: string,
    options: TransactionOptions = {},
  ): Promise<string> {
    if (!this.settlementEngine) {
      throw new Error('Settlement engine contract not initialized');
    }
    const { settlementEngine } = this;

    const perf = performanceLogger.start('Blockchain initiateSettlement');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (settlementEngine as any).initiateSettlement(
        settlementId,
        provider,
        amountWei,
        currency,
        {
          gasLimit: options.gasLimit || config.blockchain.gasLimit,
          gasPrice: options.gasPrice || config.blockchain.gasPrice,
        },
      );

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'initiateSettlement', Number(receipt.gasUsed), {
        settlementId,
        provider,
        amount,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain initiateSettlement', { settlementId });
      throw error;
    }
  }

  public async processSettlement(settlementId: string, options: TransactionOptions = {}): Promise<string> {
    if (!this.settlementEngine) {
      throw new Error('Settlement engine contract not initialized');
    }
    const { settlementEngine } = this;

    const perf = performanceLogger.start('Blockchain processSettlement');

    try {
      const tx = await (settlementEngine as any).processSettlement(settlementId, {
        gasLimit: options.gasLimit || config.blockchain.gasLimit,
        gasPrice: options.gasPrice || config.blockchain.gasPrice,
      });

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'processSettlement', Number(receipt.gasUsed), {
        settlementId,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain processSettlement', { settlementId });
      throw error;
    }
  }

  public async getSettlementStatus(settlementId: string): Promise<SettlementStatus> {
    if (!this.settlementEngine) {
      throw new Error('Settlement engine contract not initialized');
    }
    const { settlementEngine } = this;

    try {
      const status = await (settlementEngine as any).getSettlementStatus(settlementId);

      return {
        status: Number(status.status),
        amount: ethers.formatEther(status.amount),
        provider: status.provider,
        timestamp: status.timestamp.toString(),
      };
    } catch (error) {
      logger.logError(error as Error, 'Blockchain getSettlementStatus', { settlementId });
      throw error;
    }
  }

  public async addLiquidity(amount: string, options: TransactionOptions = {}): Promise<string> {
    if (!this.settlementEngine) {
      throw new Error('Settlement engine contract not initialized');
    }
    const { settlementEngine } = this;

    const perf = performanceLogger.start('Blockchain addLiquidity');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (settlementEngine as any).addLiquidity(amountWei, {
        gasLimit: options.gasLimit || config.blockchain.gasLimit,
        gasPrice: options.gasPrice || config.blockchain.gasPrice,
      });

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'addLiquidity', Number(receipt.gasUsed), {
        amount,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain addLiquidity', { amount });
      throw error;
    }
  }

  public async withdrawLiquidity(amount: string, options: TransactionOptions = {}): Promise<string> {
    if (!this.settlementEngine) {
      throw new Error('Settlement engine contract not initialized');
    }
    const { settlementEngine } = this;

    const perf = performanceLogger.start('Blockchain withdrawLiquidity');

    try {
      const amountWei = ethers.parseEther(amount);

      const tx = await (settlementEngine as any).withdrawLiquidity(amountWei, {
        gasLimit: options.gasLimit || config.blockchain.gasLimit,
        gasPrice: options.gasPrice || config.blockchain.gasPrice,
      });

      const receipt = await tx.wait();
      perf.end({ txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() });

      logger.logBlockchainTransaction(receipt.hash, 'withdrawLiquidity', Number(receipt.gasUsed), {
        amount,
      });

      return receipt.hash;
    } catch (error) {
      perf.end({ error: (error as Error).message });
      logger.logError(error as Error, 'Blockchain withdrawLiquidity', { amount });
      throw error;
    }
  }

  // Utility methods
  public async getTransactionReceipt(txHash: string): Promise<ethers.TransactionReceipt | null> {
    if (!this.provider) {
      throw new Error('Provider not initialized');
    }

    try {
      return await this.provider.getTransactionReceipt(txHash);
    } catch (error) {
      logger.logError(error as Error, 'Get transaction receipt', { txHash });
      throw error;
    }
  }

  public async getBlockNumber(): Promise<number> {
    if (!this.provider) {
      throw new Error('Provider not initialized');
    }

    try {
      return await this.provider.getBlockNumber();
    } catch (error) {
      logger.logError(error as Error, 'Get block number');
      throw error;
    }
  }

  public async getGasPrice(): Promise<string> {
    if (!this.provider) {
      throw new Error('Provider not initialized');
    }

    try {
      const gasPrice = await this.provider.getFeeData();
      return gasPrice.gasPrice?.toString() || config.blockchain.gasPrice;
    } catch (error) {
      logger.logError(error as Error, 'Get gas price');
      return config.blockchain.gasPrice;
    }
  }

  public async healthCheck(): Promise<{ status: string; blockNumber?: number; latency: number }> {
    const startTime = Date.now();

    try {
      if (!this.provider) {
        throw new Error('Provider not initialized');
      }

      const blockNumber = await this.provider.getBlockNumber();
      const latency = Date.now() - startTime;

      return {
        status: 'healthy',
        blockNumber,
        latency,
      };
    } catch (error) {
      logger.logError(error as Error, 'Blockchain health check');
      return {
        status: 'unhealthy',
        latency: Date.now() - startTime,
      };
    }
  }

  public isReady(): boolean {
    return this.isInitialized &&
           this.provider !== null &&
           this.wallet !== null &&
           this.claimsProcessor !== null &&
           this.fraudDetector !== null &&
           this.multiSigApproval !== null &&
           this.settlementEngine !== null;
  }

  public getWalletAddress(): string | null {
    return this.wallet?.address || null;
  }

  public async close(): Promise<void> {
    try {
      // Remove all event listeners
      if (this.claimsProcessor) {
        this.claimsProcessor.removeAllListeners();
      }
      if (this.fraudDetector) {
        this.fraudDetector.removeAllListeners();
      }
      if (this.multiSigApproval) {
        this.multiSigApproval.removeAllListeners();
      }
      if (this.settlementEngine) {
        this.settlementEngine.removeAllListeners();
      }

      // Destroy provider
      if (this.provider) {
        this.provider.destroy();
      }

      this.provider = null;
      this.wallet = null;
      this.claimsProcessor = null;
      this.fraudDetector = null;
      this.multiSigApproval = null;
      this.settlementEngine = null;
      this.isInitialized = false;

      logger.info('Blockchain service closed');
    } catch (error) {
      logger.logError(error as Error, 'Blockchain service shutdown');
      throw error;
    }
  }
}

// Export singleton instance
const blockchainService = BlockchainService.getInstance();
export default blockchainService;
export { BlockchainService, ClaimData, ApprovalStatus, SettlementStatus, TransactionOptions };