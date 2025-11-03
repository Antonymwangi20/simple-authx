import pino from 'pino';

export class AuditLogger {
  constructor(config = {}) {
    this.logger = pino({
      name: 'authx-audit',
      level: config.level || 'info',
      ...config.pinoOptions
    });

    this.store = config.store; // For persistent storage of audit logs
  }

  async log(event) {
    const entry = {
      timestamp: new Date(),
      event: event.type,
      user: event.username,
      ip: event.ip,
      userAgent: event.userAgent,
      success: event.success,
      details: event.details,
      sessionId: event.sessionId,
      metadata: {
        location: event.location,
        device: event.device,
        risk: event.risk
      }
    };

    // Log to pino
    this.logger.info(entry);

    // Store in persistent storage if configured
    if (this.store?.audit) {
      await this.store.audit.create(entry);
    }

    return entry;
  }

  async getAuditTrail(filters = {}) {
    if (!this.store?.audit) {
      throw new Error('Persistent audit storage not configured');
    }

    return this.store.audit.find(filters);
  }

  async getUserActivity(username, options = {}) {
    if (!this.store?.audit) {
      throw new Error('Persistent audit storage not configured');
    }

    const defaultOptions = {
      limit: 50,
      offset: 0,
      sortBy: 'timestamp',
      sortDir: 'desc',
      ...options
    };

    return this.store.audit.findByUser(username, defaultOptions);
  }

  async getSecurityEvents(severity = 'high', timeframe = '24h') {
    if (!this.store?.audit) {
      throw new Error('Persistent audit storage not configured');
    }

    const events = await this.store.audit.findSecurityEvents({
      severity,
      since: new Date(Date.now() - ms(timeframe))
    });

    return events;
  }

  // Analytics methods
  async getLoginStats(timeframe = '24h') {
    if (!this.store?.audit) return null;

    const since = new Date(Date.now() - ms(timeframe));
    const stats = await this.store.audit.aggregate([
      { $match: { event: 'login', timestamp: { $gte: since } } },
      { $group: {
        _id: '$success',
        count: { $sum: 1 },
        uniqueUsers: { $addToSet: '$user' },
        uniqueIPs: { $addToSet: '$ip' }
      }}
    ]);

    return {
      successful: stats.find(s => s._id === true)?.count || 0,
      failed: stats.find(s => s._id === false)?.count || 0,
      uniqueUsers: stats.reduce((acc, s) => acc + (s.uniqueUsers?.length || 0), 0),
      uniqueIPs: stats.reduce((acc, s) => acc + (s.uniqueIPs?.length || 0), 0)
    };
  }

  async getSecurityInsights() {
    if (!this.store?.audit) return null;

    const now = new Date();
    const dayAgo = new Date(now - ms('24h'));
    const weekAgo = new Date(now - ms('7d'));

    const insights = await this.store.audit.aggregate([
      { $match: { 
        timestamp: { $gte: weekAgo },
        event: { $in: ['login', 'password_reset', 'mfa_verify', 'token_refresh'] }
      }},
      { $group: {
        _id: {
          day: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          event: '$event',
          success: '$success'
        },
        count: { $sum: 1 }
      }}
    ]);

    return {
      dailyStats: insights.reduce((acc, i) => {
        const day = i._id.day;
        if (!acc[day]) acc[day] = {};
        const event = i._id.event;
        if (!acc[day][event]) acc[day][event] = { success: 0, failed: 0 };
        acc[day][event][i._id.success ? 'success' : 'failed'] = i.count;
        return acc;
      }, {}),
      timeframe: {
        start: weekAgo,
        end: now
      }
    };
  }
}