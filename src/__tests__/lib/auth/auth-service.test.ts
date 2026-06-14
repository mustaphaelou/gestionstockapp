import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fromAny } from '@total-typescript/shoehorn'
import { InMemoryAuthStore } from '@/lib/auth/in-memory-auth-store'
import { createAuthService, type AuthService } from '@/lib/auth/auth-service'

const { mockPrismaFindUnique, mockPrismaUpdate } = vi.hoisted(() => ({
  mockPrismaFindUnique: vi.fn(),
  mockPrismaUpdate: vi.fn(),
}))

const { mockVerifyPassword } = vi.hoisted(() => ({
  mockVerifyPassword: vi.fn(),
}))

const { mockGenerateToken, mockVerifyToken, mockRevokeToken } = vi.hoisted(() => ({
  mockGenerateToken: vi.fn(),
  mockVerifyToken: vi.fn().mockResolvedValue({ userId: 'user-1', sessionId: 'session-1', jti: 'jti-1' }),
  mockRevokeToken: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('@/lib/db/prisma', () => ({
  prisma: {
    user: {
      findUnique: mockPrismaFindUnique,
      update: mockPrismaUpdate,
    },
  },
}))

vi.mock('@/lib/auth/password', () => ({
  verifyPassword: mockVerifyPassword,
  hashPassword: vi.fn(),
}))

vi.mock('@/lib/auth/jwt', () => ({
  generateToken: mockGenerateToken,
  verifyToken: mockVerifyToken,
  revokeToken: mockRevokeToken,
}))

vi.mock('@/lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}))

describe('Auth Service', () => {
  let authService: AuthService
  let authStore: InMemoryAuthStore

  beforeEach(() => {
    vi.resetAllMocks()
    authStore = new InMemoryAuthStore()
    authService = createAuthService(authStore)
    mockVerifyPassword.mockResolvedValue(true)
    mockGenerateToken.mockResolvedValue('mock-jwt-token')
    mockPrismaFindUnique.mockResolvedValue({
      id: 'user-1',
      email: 'test@test.com',
      name: 'Test User',
      role: 'USER',
      password: 'hashed-password',
    })
    mockVerifyToken.mockResolvedValue({ userId: 'user-1', sessionId: 'session-1', jti: 'jti-1' })
  })

  describe('loginUser', () => {
    it('should login successfully with valid credentials', async () => {
      const result = await authService.loginUser('test@test.com', 'correct-password', false, '192.168.1.1')

      expect(result.error).toBeUndefined()
      expect(result.data).toBeDefined()
      expect(result.data?.user.email).toBe('test@test.com')
      expect(result.data?.token).toBe('mock-jwt-token')
      expect(mockPrismaUpdate).toHaveBeenCalled()
      expect(mockGenerateToken).toHaveBeenCalledWith({
        userId: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        sessionId: expect.any(String),
      })
    })

    it('should reject invalid password', async () => {
      mockVerifyPassword.mockResolvedValue(false)

      const result = await authService.loginUser('test@test.com', 'wrong-password', false, '192.168.1.1')

      expect(result.error).toContain('Email ou mot de passe invalide')
      const locked = await authStore.isAccountLocked('test@test.com')
      expect(locked).toBe(false)
    })

    it('should reject locked account', async () => {
      for (let i = 0; i < 5; i++) {
        mockVerifyPassword.mockResolvedValue(false)
        await authService.loginUser('test@test.com', 'wrong-password', false, '192.168.1.1')
      }

      mockVerifyPassword.mockResolvedValue(true)
      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        password: 'hashed-password',
      })

      const result = await authService.loginUser('test@test.com', 'correct-password', false, '192.168.1.1')

      expect(result.error).toContain('Compte temporairement verrouillé')
    })

    it('should reject IP-locked', async () => {
      for (let i = 0; i < 20; i++) {
        mockVerifyPassword.mockResolvedValue(false)
        mockPrismaFindUnique.mockResolvedValue(null)
        await authService.loginUser('test-' + i + '@test.com', 'wrong-password', false, '192.168.1.1')
      }

      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        password: 'hashed-password',
      })
      mockVerifyPassword.mockResolvedValue(true)

      const result = await authService.loginUser('test@test.com', 'correct-password', false, '192.168.1.1')

      expect(result.error).toContain('Trop de tentatives depuis cet emplacement')
    })

    it('should reject missing user', async () => {
      mockPrismaFindUnique.mockResolvedValue(null)

      const result = await authService.loginUser('nonexistent@test.com', 'password', false, '192.168.1.1')

      expect(result.error).toBe('Email ou mot de passe invalide')
    })

    it('should return lockout error when failed attempt triggers lockout', async () => {
      for (let i = 0; i < 4; i++) {
        mockVerifyPassword.mockResolvedValue(false)
        await authService.loginUser('test@test.com', 'wrong-password', false, '192.168.1.2')
      }

      mockVerifyPassword.mockResolvedValue(false)
      const result = await authService.loginUser('test@test.com', 'wrong-password', false, '192.168.1.2')

      expect(result.error).toContain('Compte verrouillé')
    })

    it('should return error instead of throwing when prisma.update fails', async () => {
      mockPrismaUpdate.mockRejectedValue(new Error('Database connection lost'))

      const result = await authService.loginUser('test@test.com', 'correct-password', false, '192.168.1.1')

      expect(result.error).toBeDefined()
      expect(result.error).toContain('Service de base de données')
      expect(result.data).toBeUndefined()
    })

    it('should clear failed attempts on successful login', async () => {
      mockVerifyPassword.mockResolvedValue(false)
      await authService.loginUser('test@test.com', 'wrong-password', false, '192.168.1.1')

      const lockedBefore = await authStore.isAccountLocked('test@test.com')
      expect(lockedBefore).toBe(false)

      mockVerifyPassword.mockResolvedValue(true)
      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        password: 'hashed-password',
      })

      await authService.loginUser('test@test.com', 'correct-password', false, '192.168.1.1')

      const attemptsAfter = await authStore.recordFailedAttempt('test@test.com')
      expect(attemptsAfter.remaining).toBe(4)
    })
  })

  describe('logoutUser', () => {
    it('should delete session and revoke token on valid session', async () => {
      const sessionId = await authStore.createSession('user-1', 'test@test.com', 'Test User', 'USER')
      mockVerifyToken.mockResolvedValue({ userId: 'user-1', sessionId, jti: 'jti-1' })

      const result = await authService.logoutUser('valid-token')

      expect(result.error).toBeUndefined()
      expect(result.data?.loggedOut).toBe(true)
      const session = await authStore.getSession(sessionId)
      expect(session).toBeNull()
      expect(mockRevokeToken).toHaveBeenCalledWith('jti-1')
    })

    it('should handle expired/invalid token gracefully', async () => {
      mockVerifyToken.mockResolvedValue(null)

      const result = await authService.logoutUser('expired-token')

      expect(result.error).toBeUndefined()
      expect(result.data?.loggedOut).toBe(true)
    })

    it('should handle token without sessionId', async () => {
      mockVerifyToken.mockResolvedValue(fromAny({ jti: 'jti-1' }))

      const result = await authService.logoutUser('token-without-session')

      expect(result.error).toBeUndefined()
      expect(mockRevokeToken).toHaveBeenCalledWith('jti-1')
    })
  })
})
