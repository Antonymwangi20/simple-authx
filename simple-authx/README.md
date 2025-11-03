# simple-authx

A simplified, secure authentication package for Express applications with support for MongoDB, Redis, Postgres, and file-based storage.


## Features

- 🔐 Simple JWT-based authentication *(implemented)*
- 🔄 Secure refresh token rotation *(implemented)*
- 🔒 Password security with **bcrypt** and **argon2** *(both supported, configurable)*
- 🚀 Multiple storage adapters: MongoDB, Redis, Postgres, File *(all implemented)*
- 📱 MFA support with TOTP *(implemented)*
- 🌐 OAuth/Social login support *(Google & GitHub implemented; other providers not yet)*
- 📊 Session management and tracking *(implemented)*
- 🛡️ Advanced security features *(rate limiting, IP reputation, suspicious activity detection, device fingerprinting, audit logging implemented)*

## Limitations / TODO

- Only Google and GitHub OAuth are supported out of the box.
- Documentation/examples for API usage are minimal.


## Installation

```bash
npm install simple-authx
```

## Usage Example

See `examples/demo.js` for a full Express integration example.

```js
import express from 'express';
import { createAuth } from 'simple-authx';

const app = express();
app.use(express.json());

const auth = await createAuth({
	mongodb: 'mongodb://localhost:27017/myapp',
	security: { rateLimit: true, password: { minStrength: 3 } },
	mfa: { issuer: 'MyApp' },
	sessions: true
});

app.use('/auth', auth.routes);
app.get('/profile', auth.protect, (req, res) => {
	res.json({ user: req.user });
});
```
