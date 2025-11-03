import UAParser from 'ua-parser-js';
import geoip from 'geoip-lite';

export class SessionManager {
  constructor(store) {
    this.store = store;
  }

  async createSession(userId, req) {
    const ua = new UAParser(req.headers['user-agent']);
    const ip = req.ip || req.connection.remoteAddress;
    const geo = geoip.lookup(ip);

    // Device fingerprinting: create a hash of device info
    const deviceFingerprint = crypto.createHash('sha256')
      .update([
        ua.getDevice().type,
        ua.getBrowser().name,
        ua.getOS().name,
        ip
      ].join('|'))
      .digest('hex');

    const session = {
      id: crypto.randomUUID(),
      userId,
      createdAt: new Date(),
      lastActive: new Date(),
      device: {
        type: ua.getDevice().type || 'desktop',
        browser: ua.getBrowser().name,
        os: ua.getOS().name,
        ip,
        location: geo ? {
          country: geo.country,
          city: geo.city,
          timezone: geo.timezone
        } : null,
        fingerprint: deviceFingerprint
      }
    };

    await this.store.sessions.create(session);
    return session;
  }

  async updateSession(sessionId) {
    await this.store.sessions.update(sessionId, {
      lastActive: new Date()
    });
  }

  async getSessions(userId) {
    return this.store.sessions.findByUser(userId);
  }

  async invalidateSession(sessionId) {
    await this.store.sessions.delete(sessionId);
  }

  async invalidateAllSessions(userId, exceptSessionId = null) {
    const sessions = await this.getSessions(userId);
    for (const session of sessions) {
      if (session.id !== exceptSessionId) {
        await this.invalidateSession(session.id);
      }
    }
  }

  // Security features
  async detectSuspiciousActivity(session, req) {
    const ip = req.ip || req.connection.remoteAddress;
    const geo = geoip.lookup(ip);
    
    const suspicious = [];

    // Check for IP change
    if (ip !== session.device.ip) {
      suspicious.push('IP_CHANGED');
    }

    // Check for location change
    if (geo && session.device.location) {
      if (geo.country !== session.device.location.country) {
        suspicious.push('COUNTRY_CHANGED');
      }
    }

    // Check for rapid location changes
    if (suspicious.length > 0) {
      await this.store.suspicious.create({
        sessionId: session.id,
        userId: session.userId,
        type: suspicious,
        details: {
          oldIp: session.device.ip,
          newIp: ip,
          oldLocation: session.device.location,
          newLocation: geo,
          timestamp: new Date()
        }
      });
    }

    return suspicious;
  }
}