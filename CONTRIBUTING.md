# Contributing to simple-authx

First off, thank you for considering contributing to simple-authx! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

---

## 📜 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and be patient with questions
- Focus on what is best for the community
- Show empathy towards other community members

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (code snippets, test cases)
- **Describe the behavior you observed** and what you expected
- **Include logs and error messages**
- **Specify your environment** (Node.js version, OS, database)

**Template:**

```markdown
## Bug Description

[Clear description of the bug]

## Steps to Reproduce

1. [First Step]
2. [Second Step]
3. [...]

## Expected Behavior

[What you expected to happen]

## Actual Behavior

[What actually happened]

## Environment

- simple-authx version: [e.g., 2.0.0]
- Node.js version: [e.g., 18.16.0]
- Database: [e.g., PostgreSQL 15]
- OS: [e.g., Ubuntu 22.04]

## Additional Context

[Screenshots, logs, etc.]
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **Include code examples** if applicable
- **List any drawbacks or considerations**

### Your First Code Contribution

Unsure where to begin? Look for issues tagged with:

- `good first issue` - Simple issues for beginners
- `help wanted` - Issues that need attention
- `documentation` - Documentation improvements

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add or update tests** for your changes
4. **Update documentation** if needed
5. **Ensure all tests pass**
6. **Submit a pull request**

---

## 🛠️ Development Setup

### Prerequisites

- Node.js 16+ (18+ recommended)
- npm or yarn
- PostgreSQL (optional, for database tests)
- MongoDB (optional, for database tests)
- Redis (optional, for session tests)

### Setup Steps

1. **Clone your fork:**

```bash
git clone https://github.com/YOUR_USERNAME/simple-authx.git
cd simple-authx
```

2. **Install dependencies:**

```bash
npm install
```

3. **Set up environment variables:**

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Start development databases (optional):**

```bash
# Using Docker
docker-compose up -d

# Or manually:
# PostgreSQL on port 5432
# MongoDB on port 27017
# Redis on port 6379
```

5. **Run tests:**

```bash
npm test
```

6. **Run example:**

```bash
npm run example
```

### Project Structure

```
simple-authx/
├── src/
│   ├── core/              # Core authentication logic
│   │   ├── auth.js        # AuthManager class
│   │   ├── unified-api.js # Main unified API
│   │   ├── hooks.js       # Hook system
│   │   └── rbac.js        # Role-based access control
│   ├── adapters/          # Storage adapters
│   │   ├── file-adapter.js
│   │   ├── postgresAdapter.mjs
│   │   ├── mongoAdapters.mjs
│   │   └── redisAdapter.mjs
│   ├── security/          # Security plugins
│   │   ├── mfa.js         # Multi-factor authentication
│   │   ├── social.js      # Social OAuth
│   │   ├── sessions.js    # Session management
│   │   ├── security.js    # Rate limiting & security
│   │   ├── password.js    # Password validation
│   │   └── audit.js       # Audit logging
│   └── utils/             # Utility functions
├── tests/                 # Test files
├── examples/              # Example applications
├── scripts/               # Build and utility scripts
└── docs/                  # Documentation (future)
```

---

## 🔀 Pull Request Process

### Before Submitting

1. **Update CHANGELOG.md** - Add your changes under `[Unreleased]`
2. **Run tests** - Ensure `npm test` passes
3. **Run linter** - Ensure `npm run lint` passes (if configured)
4. **Update docs** - Update README.md if you changed the API
5. **Check examples** - Ensure examples still work

### PR Title Format

Use conventional commits format:

```
<type>(<scope>): <subject>

Examples:
feat(mfa): add WebAuthn support
fix(postgres): resolve connection pool leak
docs(readme): update installation instructions
test(auth): add token rotation tests
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### PR Description Template

```markdown
## Description

[Clear description of what this PR does]

## Motivation

[Why is this change needed?]

## Changes

- [Change 1]
- [Change 2]
- [...]

## Breaking Changes

[List any breaking changes, or write "None"]

## Testing

[How did you test this?]

## Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] All tests passing
- [ ] No new warnings
```

### Review Process

1. **Automated checks** - CI must pass
2. **Code review** - At least one maintainer approval required
3. **Discussion** - Address any feedback or questions
4. **Merge** - Maintainer will merge when approved

---

## 📐 Coding Standards

### JavaScript Style

- Use ES6+ features
- Use async/await over promises
- Use arrow functions for callbacks
- Use template literals for strings
- Use destructuring when appropriate

### Naming Conventions

- **Variables/Functions**: `camelCase`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Files**: `kebab-case.js` or `camelCase.js`

### Code Examples

**Good:**

```javascript
// Async function with clear naming
async function createUser(username, password) {
  if (!username || !password) {
    throw new Error('Username and password required');
  }

  const hashedPassword = await hashPassword(password);
  return adapter.createUser(username, hashedPassword);
}

// Destructuring and arrow functions
const getUserById = async (userId) => {
  const { id, username, email } = await adapter.findUser(userId);
  return { id, username, email };
};
```

**Bad:**

```javascript
// Unclear naming and promise chains
function create_user(u, p) {
  return hashPassword(p).then((hash) => {
    return adapter.createUser(u, hash);
  });
}

// No error handling
async function getUser(userId) {
  return adapter.findUser(userId);
}
```

### Error Handling

- Always handle errors gracefully
- Use descriptive error messages
- Include error context when helpful
- Don't leak sensitive information in errors

```javascript
// Good
try {
  await auth.login(username, password);
} catch (error) {
  if (error.message.includes('credentials')) {
    throw new Error('Invalid username or password');
  }
  throw new Error('Login failed. Please try again.');
}

// Bad
try {
  await auth.login(username, password);
} catch (error) {
  throw error; // Leaks internal details
}
```

### Comments

- Write self-documenting code when possible
- Add comments for complex logic
- Use JSDoc for public APIs
- Keep comments up to date

```javascript
/**
 * Generate access and refresh tokens for a user
 * @param {Object} payload - Token payload (userId, roles, etc.)
 * @returns {Object} Object with accessToken and refreshToken
 */
generateTokens(payload) {
  const accessToken = jwt.sign(payload, this.secret, {
    expiresIn: this.accessExpiry
  });

  // Add unique JTI for token rotation tracking
  const jti = crypto.randomUUID();
  const refreshToken = jwt.sign(
    { ...payload, jti },
    this.refreshSecret,
    { expiresIn: this.refreshExpiry }
  );

  return { accessToken, refreshToken };
}
```

---

## 🧪 Testing Guidelines

### Test Structure

```javascript
// tests/test-feature.js
import assert from 'assert';
import { createAuth } from '../index.mjs';

async function testFeature() {
  console.log('📝 Test: Feature Name');

  // Setup
  const auth = await createAuth();

  // Execute
  const result = await auth.someMethod();

  // Assert
  assert(result.success, 'Should succeed');

  console.log('✅ Test passed\n');
}

// Run test
testFeature().catch(console.error);
```

### Testing Checklist

- [ ] Unit tests for new functions
- [ ] Integration tests for adapters
- [ ] E2E tests for complete flows
- [ ] Edge cases covered
- [ ] Error cases tested
- [ ] Async code properly tested

### Running Tests

```bash
# All tests
npm test

# Specific test
node tests/test-unified-api.js

# With coverage (if configured)
npm run test:coverage

# Watch mode (if configured)
npm run test:watch
```

---

## 📚 Documentation

### Documentation Standards

- **README.md** - Overview, quick start, API reference
- **MIGRATION.md** - Migration guides between versions
- **CHANGELOG.md** - All changes, following Keep a Changelog format
- **Code Comments** - JSDoc for public APIs
- **Examples** - Working code examples in `examples/`

### Updating Documentation

When adding a feature:

1. Update README.md with usage examples
2. Add entry to CHANGELOG.md under `[Unreleased]`
3. Create or update example in `examples/`
4. Add JSDoc comments to new functions
5. Update MIGRATION.md if breaking changes

### Writing Examples

- Keep examples simple and focused
- Include comments explaining key concepts
- Test that examples actually work
- Show both basic and advanced usage

---

## 🎯 Priorities

Current focus areas (see [PROGRESS.md](./PROGRESS.md)):

1. **Documentation** - Improve and expand docs
2. **Testing** - Increase test coverage
3. **Examples** - More real-world examples
4. **Performance** - Optimize database queries
5. **Security** - Security audits and improvements

---

## 💬 Communication

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community discussion
- **Pull Requests** - Code contributions

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 Thank You!

Your contributions make simple-authx better for everyone. We appreciate your time and effort!

**Questions?** Open a GitHub Discussion or reach out to the maintainers.

---

**Happy coding! 🚀**
