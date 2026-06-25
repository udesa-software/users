module.exports = {
  testMatch: ['<rootDir>/tests/unit/**/*.test.js'],
  setupFiles: ['<rootDir>/src/tests/setupEnv.js'],
  collectCoverageFrom: [
    'src/modules/users/user.service.js',
    'src/modules/auth/auth.service.js',
  ],
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
};
