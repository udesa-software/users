process.env.DB_HOST = process.env.TEST_DB_HOST || 'localhost';
process.env.DB_PORT = process.env.TEST_DB_PORT || '5433';
process.env.DB_NAME = process.env.TEST_DB_NAME || 'users_db';
process.env.DB_USER = process.env.TEST_DB_USER || 'admin';
process.env.DB_PASSWORD = process.env.TEST_DB_PASSWORD || 'secret';
process.env.JWT_SECRET = 'test-jwt-secret-integration';
process.env.APP_URL = 'http://localhost:3000';
process.env.REDIS_URL = process.env.TEST_REDIS_URL || 'redis://localhost:6379';
// Leave SMTP_HOST unset so emails silently no-op
// Leave FRIENDS_SERVICE_URL unset so the friends client call is skipped on delete
