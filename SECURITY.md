# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

**Do not** report security vulnerabilities through public GitHub issues.

Please report via email to: **antony254mm@gmail.com**

Include:

- Vulnerability description
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

Response time: Within 48 hours

## Security Features

- Bcrypt/Argon2 password hashing
- JWT token rotation
- Token reuse detection
- CSRF protection
- Rate limiting
- Session management
- Audit logging

## Best Practices

1. Use HTTPS in production
2. Set strong JWT secrets (32+ characters)
3. Enable rate limiting
4. Implement CSRF protection
5. Use httpOnly cookies
6. Regular security updates (`npm audit`)
