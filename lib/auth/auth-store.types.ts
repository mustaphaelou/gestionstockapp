export interface SessionData {
  userId: string
  email: string
  name: string
  role: string
  createdAt: number
}

export interface LockoutResult {
  locked: boolean
  remaining: number
  unlockIn?: number
  error?: string
}

export interface AuthStore {
  createSession(userId: string, email: string, name: string, role: string): Promise<string>
  getSession(sessionId: string): Promise<SessionData | null>
  deleteSession(sessionId: string): Promise<void>
  refreshSession(sessionId: string): Promise<void>

  recordFailedAttempt(email: string): Promise<LockoutResult>
  clearFailedAttempts(email: string): Promise<void>
  isAccountLocked(email: string): Promise<boolean>
  recordFailedAttemptByIp(ip: string): Promise<LockoutResult>
  isLockedByIp(ip: string): Promise<boolean>
  clearFailedAttemptsByIp(ip: string): Promise<void>
}
