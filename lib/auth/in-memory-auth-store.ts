import { randomBytesHex } from '@/lib/utils/crypto'
import type { AuthStore, SessionData, LockoutResult } from './auth-store.types'

interface AttemptWindow {
  count: number
  windowEnd: number
}

interface LockEntry {
  lockedUntil: number
}

export class InMemoryAuthStore implements AuthStore {
  private sessions = new Map<string, SessionData>()
  private lockouts = new Map<string, LockEntry>()
  private ipLockouts = new Map<string, LockEntry>()
  private attemptCounts = new Map<string, AttemptWindow>()
  private ipAttemptCounts = new Map<string, AttemptWindow>()

  async createSession(userId: string, email: string, name: string, role: string): Promise<string> {
    const sessionId = randomBytesHex(16)
    this.sessions.set(sessionId, { userId, email, name, role, createdAt: Date.now() })
    return sessionId
  }

  async getSession(sessionId: string): Promise<SessionData | null> {
    return this.sessions.get(sessionId) ?? null
  }

  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId)
  }

  async refreshSession(_sessionId: string): Promise<void> {
  }

  async recordFailedAttempt(email: string): Promise<LockoutResult> {
    const maxAttempts = 5
    const duration = 900
    const now = Date.now()

    const lockEntry = this.lockouts.get(email)
    if (lockEntry && lockEntry.lockedUntil > now) {
      const unlockIn = Math.ceil((lockEntry.lockedUntil - now) / 1000)
      return { locked: true, remaining: 0, unlockIn }
    }

    let attemptEntry = this.attemptCounts.get(email)
    if (!attemptEntry || attemptEntry.windowEnd <= now) {
      attemptEntry = { count: 1, windowEnd: now + duration * 1000 }
      this.attemptCounts.set(email, attemptEntry)
      return { locked: false, remaining: maxAttempts - 1 }
    }

    attemptEntry.count++
    if (attemptEntry.count >= maxAttempts) {
      this.lockouts.set(email, { lockedUntil: now + duration * 1000 })
      this.attemptCounts.delete(email)
      return { locked: true, remaining: 0 }
    }

    return { locked: false, remaining: maxAttempts - attemptEntry.count }
  }

  async clearFailedAttempts(email: string): Promise<void> {
    this.lockouts.delete(email)
    this.attemptCounts.delete(email)
  }

  async isAccountLocked(email: string): Promise<boolean> {
    const entry = this.lockouts.get(email)
    if (!entry) return false
    if (entry.lockedUntil <= Date.now()) {
      this.lockouts.delete(email)
      return false
    }
    return true
  }

  async recordFailedAttemptByIp(ip: string): Promise<LockoutResult> {
    const ipMaxAttempts = 20
    const duration = 900
    const now = Date.now()

    const lockEntry = this.ipLockouts.get(ip)
    if (lockEntry && lockEntry.lockedUntil > now) {
      const unlockIn = Math.ceil((lockEntry.lockedUntil - now) / 1000)
      return { locked: true, remaining: 0, unlockIn }
    }

    let attemptEntry = this.ipAttemptCounts.get(ip)
    if (!attemptEntry || attemptEntry.windowEnd <= now) {
      attemptEntry = { count: 1, windowEnd: now + duration * 1000 }
      this.ipAttemptCounts.set(ip, attemptEntry)
      return { locked: false, remaining: ipMaxAttempts - 1 }
    }

    attemptEntry.count++
    if (attemptEntry.count >= ipMaxAttempts) {
      this.ipLockouts.set(ip, { lockedUntil: now + duration * 1000 })
      this.ipAttemptCounts.delete(ip)
      return { locked: true, remaining: 0 }
    }

    return { locked: false, remaining: ipMaxAttempts - attemptEntry.count }
  }

  async isLockedByIp(ip: string): Promise<boolean> {
    const entry = this.ipLockouts.get(ip)
    if (!entry) return false
    if (entry.lockedUntil <= Date.now()) {
      this.ipLockouts.delete(ip)
      return false
    }
    return true
  }

  async clearFailedAttemptsByIp(ip: string): Promise<void> {
    this.ipLockouts.delete(ip)
    this.ipAttemptCounts.delete(ip)
  }
}
