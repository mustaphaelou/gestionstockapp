import { cache } from 'react'
import { cookies } from 'next/headers'
import { verifyToken } from '@/lib/auth/jwt'
import { AUTH_COOKIE_NAME } from '@/lib/constants/auth'
import type { AuthStore } from './auth-store.types'

export type CurrentUser = { id: string; email: string; name: string; role: string }

type AuthErrorMode = 'silent' | 'generic' | 'detailed'

interface ResolveAuthOptions {
  errorMode: AuthErrorMode
}

class AuthError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthError'
  }
}

export { AuthError }

let defaultStorePromise: Promise<AuthStore> | null = null

async function createDefaultStore(): Promise<AuthStore> {
  const { RedisAuthStore } = await import('./redis-auth-store')
  return new RedisAuthStore()
}

export function setDefaultAuthStore(store: AuthStore): void {
  defaultStorePromise = Promise.resolve(store)
}

async function getStore(store?: AuthStore): Promise<AuthStore> {
  if (store) return store
  if (!defaultStorePromise) {
    defaultStorePromise = createDefaultStore()
  }
  return defaultStorePromise
}

async function resolveAuthUser(
  options: ResolveAuthOptions = { errorMode: 'silent' },
  store?: AuthStore,
): Promise<CurrentUser> {
  const s = await getStore(store)
  const cookieStore = await cookies()
  const token = cookieStore.get(AUTH_COOKIE_NAME)?.value

  if (!token) {
    if (options.errorMode === 'detailed') throw new AuthError('Unauthorized: Authentication required')
    if (options.errorMode === 'generic') throw new AuthError('Unauthorized')
    return null as unknown as CurrentUser
  }

  const payload = await verifyToken(token)
  if (!payload) {
    if (options.errorMode === 'detailed') throw new AuthError('Unauthorized: Invalid token')
    if (options.errorMode === 'generic') throw new AuthError('Unauthorized')
    return null as unknown as CurrentUser
  }

  const session = await s.getSession(payload.sessionId)
  if (!session) {
    const redisAvailable = await s.isRedisReady()
    if (!redisAvailable) {
      return {
        id: payload.userId,
        email: payload.email ?? '',
        name: payload.name ?? '',
        role: payload.role ?? 'USER',
      }
    }
    if (options.errorMode === 'detailed') throw new AuthError('Unauthorized: Session expired or revoked')
    if (options.errorMode === 'generic') throw new AuthError('Unauthorized')
    return null as unknown as CurrentUser
  }

  return {
    id: session.userId,
    email: session.email,
    name: session.name,
    role: session.role,
  }
}

export const getCurrentUser = cache(async (store?: AuthStore): Promise<CurrentUser | null> => {
  try {
    return await resolveAuthUser({ errorMode: 'silent' }, store)
  } catch {
    return null
  }
})

export async function requireAuth(store?: AuthStore): Promise<CurrentUser> {
  try {
    const user = await resolveAuthUser({ errorMode: 'generic' }, store)
    return user
  } catch (error) {
    if (error instanceof AuthError) throw error
    throw new AuthError('Unauthorized')
  }
}

export async function requireRole(allowedRoles: string[], store?: AuthStore): Promise<CurrentUser> {
  const user = await requireAuth(store)
  if (!allowedRoles.includes(user.role)) {
    throw new Error('Forbidden')
  }
  return user
}

export async function resolveAuthUserDetailed(store?: AuthStore): Promise<CurrentUser> {
  return resolveAuthUser({ errorMode: 'detailed' }, store)
}
