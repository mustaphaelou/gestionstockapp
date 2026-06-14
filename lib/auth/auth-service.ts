import { prisma } from '@/lib/db/prisma'
import { verifyPassword } from '@/lib/auth/password'
import { generateToken, verifyToken, revokeToken } from '@/lib/auth/jwt'
import { createLogger } from '@/lib/logger'
import type { AuthStore } from './auth-store.types'

const log = createLogger('auth-service')

export interface LoginResult {
  user: { id: string; email: string; name: string; role: string }
  sessionId: string
  token: string
}

export interface AuthService {
  loginUser(
    email: string,
    password: string,
    rememberMe: boolean,
    clientIp: string,
  ): Promise<{ data?: LoginResult; error?: string }>
  logoutUser(tokenValue: string): Promise<{ data: { loggedOut: boolean }; error?: string }>
}

export function createAuthService(store: AuthStore): AuthService {
  return {
    async loginUser(email, password, _rememberMe, clientIp) {
      try {
        const [ipLocked, locked] = await Promise.all([
          store.isLockedByIp(clientIp),
          store.isAccountLocked(email),
        ])

        if (ipLocked) {
          return { error: 'Trop de tentatives depuis cet emplacement. Veuillez réessayer dans 15 minutes.' }
        }

        if (locked) {
          return { error: 'Compte temporairement verrouillé suite à trop de tentatives. Veuillez réessayer dans 15 minutes.' }
        }

        const user = await prisma.user.findUnique({ where: { email } })

        if (!user) {
          await Promise.all([store.recordFailedAttempt(email), store.recordFailedAttemptByIp(clientIp)])
          return { error: 'Email ou mot de passe invalide' }
        }

        const isValid = await verifyPassword(password, user.password)

        if (!isValid) {
          const result = await store.recordFailedAttempt(email)
          await store.recordFailedAttemptByIp(clientIp)
          if (result.locked) {
            return { error: 'Compte verrouillé suite à trop de tentatives. Veuillez réessayer dans 15 minutes.' }
          }
          return { error: `Email ou mot de passe invalide. ${result.remaining} tentative${result.remaining !== 1 ? 's' : ''} restante${result.remaining !== 1 ? 's' : ''}.` }
        }

        await Promise.all([store.clearFailedAttempts(email), store.clearFailedAttemptsByIp(clientIp)])

        const [sessionId] = await Promise.all([
          store.createSession(user.id, user.email, user.name, user.role),
          prisma.user.update({
            where: { id: user.id },
            data: { lastLoginAt: new Date() },
          }),
        ])

        const token = await generateToken({
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          sessionId,
        })

        log.debug({ email }, 'User logged in successfully')

        return {
          data: {
            user: { id: user.id, email: user.email, name: user.name, role: user.role },
            sessionId,
            token,
          },
        }
      } catch (error) {
        log.error({ error, email }, 'Login failed')
        const msg = error instanceof Error ? error.message : ''

        if (/connect|econnrefused|enotfound|timeout/i.test(msg) && !/redis|session/i.test(msg)) {
          return { error: 'Service de base de données temporairement indisponible. Veuillez réessayer.' }
        }
        return { error: 'Une erreur inattendue est survenue lors de la connexion.' }
      }
    },

    async logoutUser(tokenValue) {
      try {
        const payload = await verifyToken(tokenValue)
        if (payload?.sessionId) {
          await store.deleteSession(payload.sessionId)
        }
        if (payload?.jti) {
          await revokeToken(payload.jti)
        }
        return { data: { loggedOut: true } }
      } catch (error) {
        log.error({ error }, 'Failed to logout user')
        return { data: { loggedOut: false }, error: 'Failed to logout user' }
      }
    },
  }
}
