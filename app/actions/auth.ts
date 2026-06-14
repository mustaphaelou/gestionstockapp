'use server'

import { cookies, headers } from 'next/headers'
import { serverActionWrite } from '@/lib/actions/server-action-write'
import { createAuthService, type AuthService } from '@/lib/auth/auth-service'
import { RedisAuthStore } from '@/lib/auth/redis-auth-store'

let authService: AuthService | undefined

function getAuthService(): AuthService {
  if (!authService) {
    authService = createAuthService(new RedisAuthStore())
  }
  return authService
}
import { loginSchema } from '@/lib/auth/validation'
import { AUTH_COOKIE_NAME } from '@/lib/constants/auth'
import { getAuthConfig } from '@/lib/config/auth-config'
import { getCurrentUser } from '@/lib/auth/user-utils'

export async function login(e: string, p: string, r = false, t?: string): Promise<{ error?: string; success?: boolean }> {
  if (!t) return { error: 'Jeton de sécurité requis' }
  return serverActionWrite('public', t, async () => {
    const h = await headers()
    const ip = h.get('x-forwarded-for')?.split(',')[0]?.trim() || h.get('x-real-ip') || 'unknown'
    const d = await getAuthService().loginUser(e, p, r, ip)
    if (d.error) return { error: d.error }
    const c = await cookies()
    const { ttl } = getAuthConfig().session
    c.set(AUTH_COOKIE_NAME, d.data!.token, {
      httpOnly: true, secure: getAuthConfig().cookies.secure,
      sameSite: 'strict', maxAge: ttl, path: '/',
    })
    return { success: true, error: undefined }
  }, { validation: { schema: loginSchema, input: { email: e, password: p } } })
}

export async function logout(t?: string): Promise<{ error?: string; success?: boolean }> {
  if (!t) return { error: 'Jeton de sécurité requis' }
  return serverActionWrite('authenticated', t, async () => {
    const c = await cookies()
    const v = c.get(AUTH_COOKIE_NAME)?.value
    if (v) await getAuthService().logoutUser(v)
    c.delete(AUTH_COOKIE_NAME)
    return { success: true, error: undefined }
  })
}

export { getCurrentUser }
