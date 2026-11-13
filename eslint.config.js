// @ts-check
const eslint = require('@eslint/js');
const { defineConfig } = require('eslint/config');
const tseslint = require('typescript-eslint');
const angular = require('angular-eslint');

module.exports = defineConfig([
  {
    files: ['**/*.ts'],
    extends: [
      eslint.configs.recommended,
      tseslint.configs.recommended,
      tseslint.configs.stylistic,
      angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    rules: {
      '@angular-eslint/directive-selector': [
        'error',
        { type: 'attribute', prefix: 'dg', style: 'camelCase' },
      ],
      '@angular-eslint/component-selector': [
        'error',
        { type: 'element', prefix: 'dg', style: 'kebab-case' },
      ],

      // PROJECT_SPECIFICATION.md §4.2 — "Never use `any`", and do not resolve type
      // errors by suppressing the compiler. These are errors, not warnings.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/ban-ts-comment': [
        'error',
        { 'ts-ignore': true, 'ts-nocheck': true, 'ts-expect-error': 'allow-with-description' },
      ],
      '@typescript-eslint/no-non-null-assertion': 'error',

      // §14 — no unsafe rendering, no eval.
      'no-eval': 'error',
      'no-implied-eval': 'error',

      // §14 — no secret data in logs. `console.warn`/`error` remain available.
      'no-console': ['error', { allow: ['warn', 'error'] }],
    },
  },

  // §4.4 — the analysis engine must be pure TypeScript. This is an acceptance criterion
  // ("Engine has zero Angular imports"), so it is enforced mechanically rather than by
  // convention. A matching unit test (engine-purity.spec.ts) covers the same rule so a
  // violation fails `npm test` too, not only `npm run lint`.
  {
    files: ['src/app/engine/**/*.ts'],
    rules: {
      // The base rule cannot distinguish a type-only import from a value import, so the
      // typescript-eslint version is used instead.
      'no-restricted-imports': 'off',
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@angular/*', '@angular'],
              // Banned outright, including types: the engine has no business knowing
              // Angular exists.
              allowTypeImports: false,
              message:
                'The analysis engine must stay free of Angular (spec §4.4). Keep DI, HTTP and ' +
                'rendering in src/app/core or src/app/features and pass plain data into the engine.',
            },
            {
              group: ['**/core/**', '**/features/**'],
              // Type-only imports are permitted: they are erased at compile time, so the
              // engine can share the domain vocabulary without acquiring a runtime
              // dependency on the application layers. A value import is still rejected.
              allowTypeImports: true,
              message:
                'The engine must not depend on application layers at runtime (spec §4.4). Import ' +
                'shared models with `import type`, or pass the data in as an argument.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        { name: 'window', message: 'The engine must not touch the DOM (spec §4.4).' },
        { name: 'document', message: 'The engine must not touch the DOM (spec §4.4).' },
        { name: 'localStorage', message: 'The engine must not touch browser storage (spec §4.4).' },
        {
          name: 'fetch',
          message: 'The engine performs no I/O (spec §10.3). Pass fetched data in.',
        },
      ],
    },
  },

  {
    files: ['**/*.html'],
    extends: [angular.configs.templateRecommended, angular.configs.templateAccessibility],
    rules: {},
  },
]);
