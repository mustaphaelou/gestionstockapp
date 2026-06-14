import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryAuthStore } from '@/lib/auth/in-memory-auth-store'
import type { AuthStore } from '@/lib/auth/auth-store.types'

describe('Session Management', () => {
  let store: AuthStore

  beforeEach(() => {
    store = new InMemoryAuthStore()
  })

  describe('createSession', () => {
    it('should create session and return session ID', async () => {
      const sessionId = await store.createSession('user-123', 'test@example.com', 'Test User', 'USER')

      expect(sessionId).toBeDefined()
      expect(sessionId).toHaveLength(32)
    })

    it('should store complete session data', async () => {
      const sessionId = await store.createSession('user-123', 'test@example.com', 'Test User', 'USER')

      const data = await store.getSession(sessionId)
      expect(data).toEqual({
        userId: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        role: 'USER',
        createdAt: expect.any(Number),
      })
    })
  })

  describe('getSession', () => {
    it('should return session data for valid session', async () => {
      const sessionId = await store.createSession('user-123', 'test@example.com', 'Test User', 'USER')

      const result = await store.getSession(sessionId)

      expect(result).toEqual({
        userId: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        role: 'USER',
        createdAt: expect.any(Number),
      })
    })

    it('should return null for non-existent session', async () => {
      const result = await store.getSession('non-existent')

      expect(result).toBeNull()
    })
  })

  describe('deleteSession', () => {
    it('should delete session', async () => {
      const sessionId = await store.createSession('user-123', 'test@example.com', 'Test User', 'USER')

      await store.deleteSession(sessionId)

      const result = await store.getSession(sessionId)
      expect(result).toBeNull()
    })
  })

  describe('refreshSession', () => {
    it('should not throw for existing session', async () => {
      const sessionId = await store.createSession('user-123', 'test@example.com', 'Test User', 'USER')

      await expect(store.refreshSession(sessionId)).resolves.toBeUndefined()
    })
  })
})
