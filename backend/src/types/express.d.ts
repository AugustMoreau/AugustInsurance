import { AuthenticatedUser } from '../middleware/auth';

declare namespace Express {
  export interface Request {
    user?: AuthenticatedUser;
    sessionId?: string;
  }
}