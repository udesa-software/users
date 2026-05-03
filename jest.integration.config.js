module.exports = {
  testMatch: ['<rootDir>/tests/integration/*.integration.test.js'],
  setupFiles: ['./src/tests/setupEnv.js'],
  testTimeout: 20000,
  maxWorkers: 1,
  forceExit: true,
  coverageDirectory: 'coverage-integration',
  collectCoverageFrom: [
    'src/modules/users/user.routes.js',
    'src/modules/users/user.controller.js',
    'src/modules/users/user.service.js',
    'src/modules/users/user.repository.js',
    'src/modules/auth/auth.routes.js',
    'src/modules/auth/auth.controller.js',
    'src/modules/auth/auth.service.js',
    'src/middlewares/authenticate.js',
  ],
};
