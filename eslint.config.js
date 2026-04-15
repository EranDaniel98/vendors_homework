import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import prettier from 'eslint-config-prettier';

const envBan = {
  'no-restricted-properties': [
    'error',
    {
      object: 'process',
      property: 'env',
      message: 'Read env vars through src/config.ts only.',
    },
  ],
};

export default [
  {
    ignores: ['dist/**', 'node_modules/**', '*.db', 'tests/fixtures/**'],
  },
  {
    files: ['src/**/*.ts', 'tests/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        process: 'readonly',
        console: 'readonly',
        URL: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': 'error',
    },
  },
  {
    files: ['src/**/*.ts', 'tests/**/*.ts'],
    ignores: ['src/config.ts'],
    rules: envBan,
  },
  prettier,
];
