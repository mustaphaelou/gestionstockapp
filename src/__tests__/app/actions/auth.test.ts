import { describe, it, expect, beforeEach, vi } from 'vitest'

const { mockVerifyPassword } = vi.hoisted(() => ({
  mockVerifyPassword: vi.fn(),
}))

const { mockGenerateToken, mockVerifyToken, mockRevokeToken } = vi.hoisted(() => ({
  mockGenerateToken: vi.fn().mockResolvedValue('mock-jwt-token'),
  mockVerifyToken: vi.fn().mockResolvedValue({ userId: 'user-1', sessionId: 'session-1', jti: 'jti-1' }),
  mockRevokeToken: vi.fn().mockResolvedValue(undefined),
}))

const { mockPrismaFindUnique, mockPrismaUpdate } = vi.hoisted(() => ({
  mockPrismaFindUnique: vi.fn(),
  mockPrismaUpdate: vi.fn(),
}))

const { mockServerActionWrite } = vi.hoisted(() => ({
  mockServerActionWrite: vi.fn(),
}))

vi.mock('@/lib/db/redis', () => ({
  redis: {
    setex: vi.fn().mockResolvedValue('OK'),
    get: vi.fn(),
    del: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(1),
    exists: vi.fn().mockResolvedValue(0),
    ping: vi.fn().mockResolvedValue('PONG'),
    script: vi.fn().mockResolvedValue('script-sha'),
    evalsha: vi.fn().mockResolvedValue([0, 4, 0]),
  },
  isRedisReady: vi.fn().mockReturnValue(true),
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

vi.mock('@/lib/actions/server-action-write', () => ({
  serverActionWrite: mockServerActionWrite,
}))

vi.mock('@/lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}))

vi.mock('@/lib/auth/user-utils', () => ({
  getCurrentUser: vi.fn().mockResolvedValue({ id: 'user-1', email: 'test@example.com', name: 'Test User', role: 'USER' }),
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn().mockResolvedValue({
    get: vi.fn().mockReturnValue({ value: 'mock-auth-token' }),
    set: vi.fn(),
    delete: vi.fn(),
  }),
  headers: vi.fn().mockResolvedValue(new Map([['x-forwarded-for', '127.0.0.1']])),
}))

vi.mock('next/server', () => ({
  after: vi.fn((fn) => fn()),
}))

import * as authModule from '@/app/actions/auth'

describe('Auth Actions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPrismaFindUnique.mockReset()
    mockPrismaUpdate.mockReset()
  })

  describe('login', () => {
    it('should call serverActionWrite with public permission, csrf token, and loginSchema validation', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })

      await authModule.login('test@test.com', 'password', false, 'valid-token')

      expect(mockServerActionWrite).toHaveBeenCalledWith(
        'public', 'valid-token', expect.any(Function),
        { validation: expect.objectContaining({ schema: expect.anything(), input: { email: 'test@test.com', password: 'password' } }) },
      )
    })

    it('should reject non-existent user inside writeFn', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })
      mockPrismaFindUnique.mockResolvedValue(null)

      const result = await authModule.login('nonexistent@test.com', 'password', false, 'valid-token')

      expect(result.error).toBe('Email ou mot de passe invalide')
    })

    it('should reject wrong password inside writeFn', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })
      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        password: 'hashed-password',
      })
      mockVerifyPassword.mockResolvedValue(false)

      const result = await authModule.login('test@test.com', 'wrong-password', false, 'valid-token')

      expect(result.error).toContain('Email ou mot de passe invalide')
    })

    it('should login successfully with valid credentials inside writeFn', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })
      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        password: 'hashed-password',
      })
      mockVerifyPassword.mockResolvedValue(true)

      const result = await authModule.login('test@test.com', 'correct-password', false, 'valid-token')

      expect(result.success).toBe(true)
      expect(mockGenerateToken).toHaveBeenCalled()
    })

    it('should clear lockout on successful login inside writeFn', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })
      mockPrismaFindUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@test.com',
        name: 'Test User',
        role: 'USER',
        password: 'hashed-password',
      })
      mockVerifyPassword.mockResolvedValue(true)

      await authModule.login('test@test.com', 'correct-password', false, 'valid-token')

      expect(mockPrismaUpdate).toHaveBeenCalled()
    })

    it('should return CSRF error when serverActionWrite returns CSRF error', async () => {
      mockServerActionWrite.mockResolvedValue({ error: 'Jeton de sécurité invalide. Veuillez rafraîchir la page et réessayer.' })

      const result = await authModule.login('test@test.com', 'password', false, 'bad-token')

      expect(result.error).toContain('Jeton de sécurité invalide')
    })

    it('should return validation error when serverActionWrite returns validation error', async () => {
      mockServerActionWrite.mockResolvedValue({ error: 'Entrée invalide : Adresse email invalide' })

      const result = await authModule.login('', '', false, 'valid-token')

      expect(result.error).toContain('Entrée invalide')
    })
  })

  describe('logout', () => {
    it('should call serverActionWrite with authenticated permission', async () => {
      mockServerActionWrite.mockImplementation(async (_permission: string, _csrfToken: string, writeFn: () => Promise<unknown>) => {
        return writeFn()
      })

      const result = await authModule.logout('valid-csrf-token')

      expect(mockServerActionWrite).toHaveBeenCalledWith(
        'authenticated', 'valid-csrf-token', expect.any(Function),
      )
      expect(result.success).toBe(true)
      expect(mockRevokeToken).toHaveBeenCalled()
    })

    it('should return CSRF error when serverActionWrite returns CSRF error', async () => {
      mockServerActionWrite.mockResolvedValue({ error: 'Jeton de sécurité invalide. Veuillez rafraîchir la page et réessayer.' })

      const result = await authModule.logout('bad-token')

      expect(result.error).toContain('Jeton de sécurité invalide')
    })
  })

  describe('getCurrentUser', () => {
    it('should return user from cached version', async () => {
      const user = await authModule.getCurrentUser()

      expect(user).toBeDefined()
      expect(user?.email).toBe('test@example.com')
    })
  })
})
