import { describe, it, before, after } from 'mocha';
import { expect } from 'chai';
import express from 'express';
import request from 'supertest';
import { initializeAuth, getAuth, resetAuth } from '../../index.mjs';

describe('Complete Authentication Flow', () => {
  let app;
  let server;

  before(async () => {
    app = express();
    app.use(express.json());

    await initializeAuth({
      storage: 'memory',
      secret: 'test-secret-integration',
      refreshSecret: 'test-refresh-integration',
    });

    const auth = getAuth();
    app.use('/auth', auth.routes);

    app.get('/protected', auth.protect, (req, res) => {
      res.json({ user: req.user });
    });

    server = app.listen(0);
  });

  after(() => {
    if (server) server.close();
    resetAuth();
  });

  it('should complete full registration and login flow', async function () {
    this.timeout(10000); // Increase timeout to 10s
    // Register
    const registerRes = await request(app)
      .post('/auth/register')
      .send({
        email: 'flow@example.com',
        password: 'FlowP@ss123',
      })
      .expect(200);

    expect(registerRes.body).to.have.property('accessToken');
    expect(registerRes.body.user).to.have.property('email', 'flow@example.com');

    // Access protected route
    const protectedRes = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${registerRes.body.accessToken}`)
      .expect(200);

    expect(protectedRes.body.user).to.have.property('userId');

    // Login
    const loginRes = await request(app)
      .post('/auth/login')
      .send({
        identifier: 'flow@example.com',
        password: 'FlowP@ss123',
      })
      .expect(200);

    expect(loginRes.body).to.have.property('accessToken');
  });
});
