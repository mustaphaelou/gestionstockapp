import { createLogger } from '@/lib/logger'
import { getAuthConfig } from '@/lib/config/auth-config'
import { randomBytesHex } from '@/lib/utils/crypto'
import { createHash } from 'node:crypto'
import type { AuthStore, SessionData, LockoutResult } from './auth-store.types'

const log = createLogger('redis-auth-store')

const SESSION_PREFIX = 'session:'
const LOCKOUT_PREFIX = 'lockout:'
const ATTEMPTS_PREFIX = 'attempts:'
const IP_LOCKOUT_PREFIX = 'lockout:ip:'
const IP_ATTEMPTS_PREFIX = 'attempts:ip:'

const LOCKOUT_SCRIPT = `
local lockoutKey = KEYS[1]
local attemptsKey = KEYS[2]
local lockoutDuration = tonumber(ARGV[1])
local maxAttempts = tonumber(ARGV[2])

local locked = redis.call('EXISTS', lockoutKey)
if locked == 1 then
  local ttl = redis.call('TTL', lockoutKey)
  return {1, 0, ttl}
end

local attempts = redis.call('INCR', attemptsKey)
if attempts == 1 then
  redis.call('EXPIRE', attemptsKey, lockoutDuration)
end

if attempts >= maxAttempts then
  redis.call('SETEX', lockoutKey, lockoutDuration, '1')
  redis.call('DEL', attemptsKey)
  return {1, 0, 0}
end

return {0, maxAttempts - attempts, 0}
`

export class RedisAuthStore implements AuthStore {
  private lockoutScriptSha: string | null = null

  async createSession(userId: string, email: string, name: string, role: string): Promise<string> {
    const sessionId = randomBytesHex(16)
    const sessionData: SessionData = { userId, email, name, role, createdAt: Date.now() }
    const redisClient = await this.getRedis()
    if (redisClient) {
      await redisClient.setex(
        `${SESSION_PREFIX}${sessionId}`,
        getAuthConfig().session.ttl,
        JSON.stringify(sessionData),
      )
    }
    return sessionId
  }

  async getSession(sessionId: string): Promise<SessionData | null> {
    const redisClient = await this.getRedis()
    if (!redisClient) return null
    const key = `${SESSION_PREFIX}${sessionId}`
    const data = await redisClient.get(key)
    if (!data) return null
    try {
      return JSON.parse(data) as SessionData
    } catch {
      log.error({ key }, 'Failed to parse session data')
      return null
    }
  }

  async deleteSession(sessionId: string): Promise<void> {
    const redisClient = await this.getRedis()
    if (!redisClient) return
    await redisClient.del(`${SESSION_PREFIX}${sessionId}`)
  }

  async refreshSession(sessionId: string): Promise<void> {
    const redisClient = await this.getRedis()
    if (!redisClient) return
    await redisClient.expire(`${SESSION_PREFIX}${sessionId}`, getAuthConfig().session.ttl)
  }

  async recordFailedAttempt(email: string): Promise<LockoutResult> {
    const { maxAttempts, duration } = getAuthConfig().lockout
    const lockoutKey = `${LOCKOUT_PREFIX}${email}`
    const attemptsKey = `${ATTEMPTS_PREFIX}${email}`
    return this.safeRedisOp(async () => {
      const result = await this.executeLockoutScript(lockoutKey, attemptsKey, maxAttempts, duration)
      if (result.locked && result.unlockIn > 0) {
        log.info({ email: email.substring(0, 3) + '***', ttl: result.unlockIn }, 'Account is locked')
      } else if (result.locked) {
        log.warn({ email: email.substring(0, 3) + '***' }, 'Account locked due to too many attempts')
      } else {
        log.info({ email: email.substring(0, 3) + '***', remaining: result.remaining }, 'Failed login attempt recorded')
      }
      return { locked: result.locked, remaining: result.remaining, unlockIn: result.unlockIn || undefined }
    }, { locked: false, remaining: maxAttempts, unlockIn: undefined }, 'recordFailedAttempt')
  }

  async clearFailedAttempts(email: string): Promise<void> {
    return this.safeRedisOp(
      () => this.withRedis((r) => r.del(`${ATTEMPTS_PREFIX}${email}`)),
      undefined,
      'clearFailedAttempts',
    )
  }

  async isAccountLocked(email: string): Promise<boolean> {
    return this.safeRedisOp(
      () => this.withRedis((r) => r.exists(`${LOCKOUT_PREFIX}${email}`).then((r2: number) => r2 === 1)),
      false,
      'isAccountLocked',
    )
  }

  async recordFailedAttemptByIp(ip: string): Promise<LockoutResult> {
    const { ipMaxAttempts, duration } = getAuthConfig().lockout
    const ipHash = this.hashIp(ip)
    const lockoutKey = `${IP_LOCKOUT_PREFIX}${ipHash}`
    const attemptsKey = `${IP_ATTEMPTS_PREFIX}${ipHash}`
    return this.safeRedisOp(async () => {
      const result = await this.executeLockoutScript(lockoutKey, attemptsKey, ipMaxAttempts, duration)
      if (result.locked) {
        log.warn({ ipHash }, 'IP locked due to too many attempts')
      } else {
        log.info({ ipHash, remaining: result.remaining }, 'Failed login attempt recorded for IP')
      }
      return { locked: result.locked, remaining: result.remaining, unlockIn: result.unlockIn || undefined }
    }, { locked: false, remaining: ipMaxAttempts, unlockIn: undefined }, 'recordFailedAttemptByIp')
  }

  async isLockedByIp(ip: string): Promise<boolean> {
    const ipHash = this.hashIp(ip)
    return this.safeRedisOp(
      () => this.withRedis((r) => r.exists(`${IP_LOCKOUT_PREFIX}${ipHash}`).then((r2: number) => r2 === 1)),
      false,
      'isLockedByIp',
    )
  }

  async clearFailedAttemptsByIp(ip: string): Promise<void> {
    const ipHash = this.hashIp(ip)
    return this.safeRedisOp(
      () => this.withRedis((r) => r.del(`${IP_ATTEMPTS_PREFIX}${ipHash}`)),
      undefined,
      'clearFailedAttemptsByIp',
    )
  }

  async isRedisReady(): Promise<boolean> {
    const { isRedisReady: checkReady } = await import('@/lib/db/redis')
    return checkReady()
  }

  private async getRedis(): Promise<import('@/lib/db/redis').RedisClient | null> {
    try {
      const { redis, isRedisReady } = await import('@/lib/db/redis')
      if (!isRedisReady()) {
        log.warn('Redis not ready — session operations degraded')
        return null
      }
      await redis.ping()
      return redis
    } catch (error) {
      log.warn({ error }, 'Redis unavailable — session operations degraded')
      return null
    }
  }

  private async withRedis<T>(fn: (redis: import('@/lib/db/redis').RedisClient) => Promise<T>): Promise<T> {
    const { redis, isRedisReady } = await import('@/lib/db/redis')
    if (!isRedisReady()) throw new Error('Redis not ready')
    return fn(redis)
  }

  private async safeRedisOp<T>(op: () => Promise<T>, fallback: T, operationName: string): Promise<T> {
    const { failClosed: lockoutFailClosed } = getAuthConfig().lockout
    try {
      const { isRedisReady } = await import('@/lib/db/redis')
      if (!isRedisReady()) {
        log.warn({ operation: operationName, failClosed: lockoutFailClosed }, 'Redis not ready')
        if (lockoutFailClosed) {
          throw new Error('Service temporarily unavailable')
        }
        return fallback
      }
      return await op()
    } catch (error) {
      if (error instanceof Error && error.message === 'Service temporarily unavailable') {
        throw error
      }
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      log.error({ operation: operationName, error: errorMessage }, 'Redis operation failed')
      if (lockoutFailClosed) {
        throw new Error('Service temporarily unavailable')
      }
      return fallback
    }
  }

  private async executeLockoutScript(
    lockoutKey: string,
    attemptsKey: string,
    maxAttempts: number,
    duration: number,
  ): Promise<{ locked: boolean; remaining: number; unlockIn: number }> {
    const { redis } = await import('@/lib/db/redis')
    if (!this.lockoutScriptSha) {
      this.lockoutScriptSha = await redis.script('LOAD', LOCKOUT_SCRIPT) as string
    }
    const result = await redis.evalsha(
      this.lockoutScriptSha, 2, lockoutKey, attemptsKey,
      String(duration), String(maxAttempts),
    ) as [number, number, number]
    return { locked: result[0] === 1, remaining: result[1], unlockIn: result[2] }
  }

  private hashIp(ip: string): string {
    return createHash('sha256').update(ip).digest('hex').slice(0, 16)
  }
}
