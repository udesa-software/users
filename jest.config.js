module.exports = {
  testMatch: ['<rootDir>/tests/**/*.test.js'],
  collectCoverageFrom: [
    'src/modules/users/user.service.js',
    'src/modules/auth/auth.service.js',
    'src/modules/admin-auth/admin-auth.service.js',
    'src/modules/admins/admin.service.js',
  ],
};
