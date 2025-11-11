import { describe, it } from 'mocha';
import { expect } from 'chai';
import express from 'express';
import request from 'supertest';
import { requireRole, requireAnyRole } from '../../src/core/rbac.js';

describe('RBAC (Role-Based Access Control)', () => {
  describe('requireRole', () => {
    it('should allow access when user has required role', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/admin',
        (req, res, next) => {
          req.user = { userId: '123', role: 'admin' };
          next();
        },
        requireRole('admin'),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/admin')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.message).to.equal('Access granted');
          return done();
        });
    });

    it('should deny access when user lacks required role', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/admin',
        (req, res, next) => {
          req.user = { userId: '123', role: 'user' };
          next();
        },
        requireRole('admin'),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/admin')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });

    it('should deny access when user has no role', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/admin',
        (req, res, next) => {
          req.user = { userId: '123' };
          next();
        },
        requireRole('admin'),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/admin')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });

    it('should deny access when req.user is undefined', (done) => {
      const app = express();
      app.use(express.json());

      app.get('/admin', requireRole('admin'), (req, res) => {
        res.json({ message: 'Access granted' });
      });

      request(app)
        .get('/admin')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });
  });

  describe('requireAnyRole', () => {
    it('should allow access when user has one of the required roles', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/moderators',
        (req, res, next) => {
          req.user = { userId: '123', role: 'moderator' };
          next();
        },
        requireAnyRole(['admin', 'moderator']),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/moderators')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.message).to.equal('Access granted');
          return done();
        });
    });

    it('should allow access when user has admin role', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/moderators',
        (req, res, next) => {
          req.user = { userId: '123', role: 'admin' };
          next();
        },
        requireAnyRole(['admin', 'moderator']),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/moderators')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.message).to.equal('Access granted');
          return done();
        });
    });

    it('should deny access when user has none of the required roles', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/moderators',
        (req, res, next) => {
          req.user = { userId: '123', role: 'user' };
          next();
        },
        requireAnyRole(['admin', 'moderator']),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/moderators')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });

    it('should handle empty roles array', (done) => {
      const app = express();
      app.use(express.json());

      app.get(
        '/test',
        (req, res, next) => {
          req.user = { userId: '123', role: 'admin' };
          next();
        },
        requireAnyRole([]),
        (req, res) => {
          res.json({ message: 'Access granted' });
        }
      );

      request(app)
        .get('/test')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });

    it('should handle undefined req.user', (done) => {
      const app = express();
      app.use(express.json());

      app.get('/test', requireAnyRole(['admin']), (req, res) => {
        res.json({ message: 'Access granted' });
      });

      request(app)
        .get('/test')
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).to.equal('Forbidden');
          return done();
        });
    });
  });
});
