import js from '@eslint/js';
import importPlugin from 'eslint-plugin-import';
import prettierConfig from 'eslint-config-prettier';

export default [
  // Global ignores (applied to all subsequent configs)
  {
    ignores: [
      'docs/**',
      'coverage/**',
      'node_modules/**',
      '*.min.js',
      '.nyc_output/**',
      'dist/**',
      'build/**',
    ],
  },

  // Base configuration for all JS/MJS files
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        // Node.js globals
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        global: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        // ES2022 globals
        Promise: 'readonly',
        Set: 'readonly',
        Map: 'readonly',
        WeakMap: 'readonly',
        WeakSet: 'readonly',
        Symbol: 'readonly',
        // Mocha globals for testing
        describe: 'readonly',
        it: 'readonly',
        before: 'readonly',
        after: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        context: 'readonly',
      },
    },
    plugins: {
      import: importPlugin,
    },
    rules: {
      ...js.configs.recommended.rules,
      // Custom rules from original config
      'no-console': 'off',
      'import/extensions': ['error', 'ignorePackages'],
      'import/prefer-default-export': 'off',
      'import/no-unresolved': ['error', { ignore: ['^simple-authx$'] }],
      'max-len': [
        'error',
        {
          code: 120,
          ignoreComments: true,
          ignoreStrings: true,
        },
      ],
      'no-underscore-dangle': [
        'error',
        {
          allow: ['_map', '_id'],
        },
      ],
      'class-methods-use-this': 'off',
      'consistent-return': ['warn', { treatUndefinedAsUnspecified: true }],
      'no-param-reassign': ['error', { props: false }],
    },
  },

  // Override for examples
  {
    files: ['examples/**/*.js'],
    rules: {
      'import/no-unresolved': 'off',
      'import/no-duplicates': 'off',
      'consistent-return': 'off',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^next$' }],
    },
  },

  // Override for specific config files
  {
    files: ['src/config/env.js'],
    rules: {
      'import/no-unresolved': 'off',
    },
  },

  // Override for auth core
  {
    files: ['src/core/auth.js'],
    rules: {
      'no-restricted-syntax': 'off',
      'no-await-in-loop': 'off',
    },
  },

  // Override for specific security files
  {
    files: ['src/core/simplified.js', 'src/security/security.js'],
    rules: {
      'consistent-return': 'off',
    },
  },

  // Override for tests
  {
    files: ['tests/**/*.js'],
    rules: {
      'func-names': 'off',
    },
  },

  // Prettier config should be last to override formatting rules
  prettierConfig,
];
