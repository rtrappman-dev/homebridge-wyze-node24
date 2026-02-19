const eslint = require('@eslint/js')

module.exports = [
  {
    ignores: ['dist/**'],
  },
  {
    files: ['src/**/*.js'],
    ...eslint.configs.recommended,
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        module: 'readonly',
        require: 'readonly',
        __dirname: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
      },
    },
    rules: {
      ...eslint.configs.recommended.rules,
      'no-console': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
      curly: 'off',
      'brace-style': 'off',
      eqeqeq: 'off',
      'max-len': 'off',
      'no-fallthrough': 'off',
    },
  },
]
