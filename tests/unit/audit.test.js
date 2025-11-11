import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import { AuditLogger } from '../../src/security/audit.js';

describe('Audit Logger', () => {
  let auditLogger;

  beforeEach(() => {
    auditLogger = new AuditLogger({
      events: ['login', 'register', 'logout'],
      storage: 'console',
    });
  });

  describe('log', () => {
    it('should log an event without throwing', async () => {
      const result = await auditLogger.log({
        type: 'login',
        username: 'user123',
        success: true,
      });
      expect(result).to.have.property('event', 'login');
    });

    it('should log event with metadata', async () => {
      const result = await auditLogger.log({
        type: 'register',
        username: 'user456',
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        success: true,
      });
      expect(result).to.have.property('event', 'register');
      expect(result).to.have.property('ip', '127.0.0.1');
    });

    it('should log event without username', async () => {
      const result = await auditLogger.log({
        type: 'system_start',
        success: true,
      });
      expect(result).to.have.property('event', 'system_start');
    });

    it('should handle various event types', async () => {
      const events = ['login', 'register', 'logout', 'password_change', 'mfa_enabled'];
      await events.reduce(async (promise, eventType) => {
        await promise;
        const result = await auditLogger.log({
          type: eventType,
          username: 'user123',
          success: true,
        });
        expect(result).to.have.property('event', eventType);
      }, Promise.resolve());
    });
  });

  describe('Configuration Options', () => {
    it('should work with file storage', () => {
      const fileLogger = new AuditLogger({
        storage: 'file',
        events: ['login'],
      });
      expect(fileLogger).to.be.instanceOf(AuditLogger);
    });

    it('should work with database storage', () => {
      const dbLogger = new AuditLogger({
        storage: 'database',
        events: ['login'],
      });
      expect(dbLogger).to.be.instanceOf(AuditLogger);
    });

    it('should work with console storage', () => {
      const consoleLogger = new AuditLogger({
        storage: 'console',
        events: ['login'],
      });
      expect(consoleLogger).to.be.instanceOf(AuditLogger);
    });

    it('should work with custom retention days', () => {
      const logger = new AuditLogger({
        retentionDays: 30,
        events: ['login'],
      });
      expect(logger).to.be.instanceOf(AuditLogger);
    });

    it('should work with includeMetadata option', () => {
      const logger = new AuditLogger({
        includeMetadata: true,
        events: ['login'],
      });
      expect(logger).to.be.instanceOf(AuditLogger);
    });
  });
});
