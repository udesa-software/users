module.exports = {
  testMatch: ['<rootDir>/tests/unit/**/*.test.js'],
  collectCoverageFrom: [
    'src/modules/users/user.service.js',
    'src/modules/auth/auth.service.js',
  ],
};
