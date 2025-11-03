import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import ms from 'ms';

export class SecurityManager {
  constructor(config = {}) {
    this.redis = config.redis;
    this.ipBlockDuration = ms(config.ipBlockDuration || '24h');
    this.maxFailedAttempts = config.maxFailedAttempts || 5;
    this.attemptWindow = ms(config.attemptWindow || '15m');
  }

  createRateLimiter(options = {}) {
    const config = {
      windowMs: ms(options.window || '15m'),
      max: options.max || 100,
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: options.skipSuccessful || false,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Too many requests',
          retryAfter: Math.ceil(options.windowMs / 1000),
          code: 'RATE_LIMIT_EXCEEDED'
        });
      }
    };

    if (this.redis) {
      config.store = new RedisStore({
        sendCommand: (...args) => this.redis.sendCommand(args),
        prefix: options.prefix || 'rl:'
      });
    }

    return rateLimit(config);
  }

  async trackLoginAttempt(username, ip, success) {
    if (!this.redis) return;

    const now = Date.now();
    const userKey = `auth:attempts:user:${username}`;
    const ipKey = `auth:attempts:ip:${ip}`;

    if (success) {
      // Clear failed attempts on success
      await this.redis.del(userKey);
      await this.redis.del(ipKey);
      return;
    }

    // Track failed attempts
    const multi = this.redis.multi();
    
    // Add attempt with timestamp
    multi.zadd(userKey, now, now.toString());
    multi.zadd(ipKey, now, now.toString());
    
    // Remove old attempts outside window
    const cutoff = now - this.attemptWindow;
    multi.zremrangebyscore(userKey, 0, cutoff);
    multi.zremrangebyscore(ipKey, 0, cutoff);
    
    // Set expiry
    multi.expire(userKey, Math.ceil(this.attemptWindow / 1000));
    multi.expire(ipKey, Math.ceil(this.ipBlockDuration / 1000));

    const [userAttempts, ipAttempts] = await multi.exec();

    return {
      userBlocked: userAttempts >= this.maxFailedAttempts,
      ipBlocked: ipAttempts >= this.maxFailedAttempts * 2 // IP gets double the attempts
    };
  }

  async isBlocked(username, ip) {
    if (!this.redis) return false;

    const userKey = `auth:attempts:user:${username}`;
    const ipKey = `auth:attempts:ip:${ip}`;
    const now = Date.now();
    const cutoff = now - this.attemptWindow;

    const [userAttempts, ipAttempts] = await Promise.all([
      this.redis.zcount(userKey, cutoff, '+inf'),
      this.redis.zcount(ipKey, cutoff, '+inf')
    ]);

    return {
      userBlocked: userAttempts >= this.maxFailedAttempts,
      ipBlocked: ipAttempts >= this.maxFailedAttempts * 2,
      remainingAttempts: Math.min(
        this.maxFailedAttempts - userAttempts,
        (this.maxFailedAttempts * 2) - ipAttempts
      )
    };
  }

  // IP Intelligence
  async trackIPActivity(ip) {
    if (!this.redis) return;

    const key = `auth:ip:${ip}`;
    const now = Date.now();

    await this.redis.zadd(key, now, now.toString());
    
    // Get activity count in last hour
    const hourAgo = now - ms('1h');
    const recentActivity = await this.redis.zcount(key, hourAgo, '+inf');

    // Cleanup old data
    await this.redis.zremrangebyscore(key, 0, hourAgo);
    
    return recentActivity;
  }

  async getIPReputation(ip) {
    if (!this.redis) return 'unknown';

    const blockKey = `auth:attempts:ip:${ip}`;
    const activityKey = `auth:ip:${ip}`;
    const now = Date.now();

    const [failedAttempts, recentActivity] = await Promise.all([
      this.redis.zcount(blockKey, now - this.attemptWindow, '+inf'),
      this.redis.zcount(activityKey, now - ms('24h'), '+inf')
    ]);

    if (failedAttempts >= this.maxFailedAttempts * 2) return 'blocked';
    if (failedAttempts >= this.maxFailedAttempts) return 'suspicious';
    if (recentActivity > 1000) return 'high_activity';
    if (recentActivity > 100) return 'medium_activity';
    return 'normal';
  }
}