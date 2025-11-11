import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import { SessionManager } from '../../src/security/sessions.js';

describe('Session Manager', () => {
  let sessionManager;
  let mockStore;

  beforeEach(() => {
    // Create mock store with sessions interface
    const sessions = new Map();
    mockStore = {
      sessions: {
        create: async (session) => {
          sessions.set(session.id, session);
          return session;
        },
        findByUser: async (userId) =>
          Array.from(sessions.values()).filter((s) => s.userId === userId),
        update: async (sessionId, updates) => {
          const session = sessions.get(sessionId);
          if (session) {
            Object.assign(session, updates);
            sessions.set(sessionId, session);
          }
        },
        delete: async (sessionId) => {
          sessions.delete(sessionId);
        },
      },
      suspicious: {
        create: async (data) => data,
      },
    };
    sessionManager = new SessionManager(mockStore);
  });

  describe('createSession', () => {
    it('should create a new session', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {
          'user-agent': 'test-agent',
        },
      };

      const session = await sessionManager.createSession('user123', req);

      expect(session).to.have.property('id');
      expect(session).to.have.property('userId', 'user123');
      expect(session).to.have.property('createdAt');
      expect(session).to.have.property('lastActive');
      expect(session).to.have.property('device');
    });

    it('should include device information in session', async () => {
      const req = {
        ip: '192.168.1.1',
        headers: {
          'user-agent': 'Mozilla/5.0 Test Browser',
        },
      };

      const session = await sessionManager.createSession('user456', req);

      expect(session.device).to.have.property('ip', '192.168.1.1');
      expect(session.device).to.have.property('fingerprint');
    });
  });

  describe('updateSession', () => {
    it('should update session activity timestamp', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      const session = await sessionManager.createSession('user123', req);
      const initialTime = new Date(session.lastActive);

      // Wait a bit
      await new Promise((resolve) => {
        setTimeout(resolve, 10);
      });

      await sessionManager.updateSession(session.id);
      const updatedSessions = await sessionManager.getSessions('user123');
      const updatedSession = updatedSessions.find((s) => s.id === session.id);

      expect(updatedSession).to.exist;
      expect(new Date(updatedSession.lastActive).getTime()).to.be.greaterThan(
        initialTime.getTime()
      );
    });
  });

  describe('getSessions', () => {
    it('should get all sessions for a user', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      await sessionManager.createSession('user123', req);
      await sessionManager.createSession('user123', req);

      const sessions = await sessionManager.getSessions('user123');
      expect(sessions).to.be.an('array');
      expect(sessions.length).to.be.at.least(2);
    });

    it('should return empty array for user with no sessions', async () => {
      const sessions = await sessionManager.getSessions('nonexistent');
      expect(sessions).to.be.an('array');
      expect(sessions.length).to.equal(0);
    });
  });

  describe('invalidateSession', () => {
    it('should invalidate a specific session', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      const session = await sessionManager.createSession('user123', req);
      await sessionManager.invalidateSession(session.id);

      const sessions = await sessionManager.getSessions('user123');
      const found = sessions.find((s) => s.id === session.id);
      expect(found).to.be.undefined;
    });
  });

  describe('invalidateAllSessions', () => {
    it('should invalidate all sessions for a user', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      await sessionManager.createSession('user123', req);
      await sessionManager.createSession('user123', req);
      await sessionManager.invalidateAllSessions('user123');

      const sessions = await sessionManager.getSessions('user123');
      expect(sessions.length).to.equal(0);
    });

    it('should keep current session when specified', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      const session1 = await sessionManager.createSession('user123', req);
      await sessionManager.createSession('user123', req);

      await sessionManager.invalidateAllSessions('user123', session1.id);

      const sessions = await sessionManager.getSessions('user123');
      expect(sessions.length).to.equal(1);
      expect(sessions[0].id).to.equal(session1.id);
    });
  });

  describe('detectSuspiciousActivity', () => {
    it('should detect suspicious activity in session', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test' },
      };

      const session = await sessionManager.createSession('user123', req);
      const suspicious = await sessionManager.detectSuspiciousActivity(session, req);

      expect(suspicious).to.be.an('array');
    });
  });
});
