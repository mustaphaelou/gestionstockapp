import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryAuthStore } from '@/lib/auth/in-memory-auth-store'
import type { AuthStore } from '@/lib/auth/auth-store.types'

describe('Account Lockout', () => {
  let store: AuthStore
  const testEmail = 'test@example.com'

  beforeEach(() => {
    store = new InMemoryAuthStore()
  })

  describe('recordFailedAttempt', () => {
    it('should return remaining attempts on first failure', async () => {
      const result = await store.recordFailedAttempt(testEmail)

      expect(result.locked).toBe(false)
      expect(result.remaining).toBe(4)
    })

    it('should lock account after 5 failed attempts', async () => {
      for (let i = 0; i < 4; i++) {
        await store.recordFailedAttempt(testEmail)
      }

      const result = await store.recordFailedAttempt(testEmail)

      expect(result.locked).toBe(true)
      expect(result.remaining).toBe(0)
    })

    it('should return locked status if already locked', async () => {
      for (let i = 0; i < 5; i++) {
        await store.recordFailedAttempt(testEmail)
      }

      const result = await store.recordFailedAttempt(testEmail)

      expect(result.locked).toBe(true)
      expect(result.unlockIn).toBeGreaterThan(0)
    })
  })

  describe('clearFailedAttempts', () => {
    it('should clear attempts and unlock account', async () => {
      for (let i = 0; i < 3; i++) {
        await store.recordFailedAttempt(testEmail)
      }

      await store.clearFailedAttempts(testEmail)

      const result = await store.recordFailedAttempt(testEmail)
      expect(result.locked).toBe(false)
      expect(result.remaining).toBe(4)
    })
  })

  describe('isAccountLocked', () => {
    it('should return true when locked', async () => {
      for (let i = 0; i < 5; i++) {
        await store.recordFailedAttempt(testEmail)
      }

      const locked = await store.isAccountLocked(testEmail)

      expect(locked).toBe(true)
    })

    it('should return false when not locked', async () => {
      const locked = await store.isAccountLocked(testEmail)

      expect(locked).toBe(false)
    })
  })
})
