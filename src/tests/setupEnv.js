// Configura las variables de entorno para los tests de integración
// ANTES de que cualquier módulo de la app sea cargado por require().
// Este archivo se ejecuta vía setupFiles en jest.integration.config.js.

process.env.DB_HOST     = process.env.TEST_DB_HOST     || 'localhost';
process.env.DB_PORT     = process.env.TEST_DB_PORT     || '5433';
process.env.DB_NAME     = process.env.TEST_DB_NAME     || 'users_db';
process.env.DB_USER     = process.env.TEST_DB_USER     || 'admin';
process.env.DB_PASSWORD = process.env.TEST_DB_PASSWORD || 'secret';

// Pool de admin para migraciones — en tests usamos el mismo usuario para simplificar
process.env.DB_ADMIN_USER     = process.env.TEST_DB_ADMIN_USER     || process.env.TEST_DB_USER     || 'admin';
process.env.DB_ADMIN_PASSWORD = process.env.TEST_DB_ADMIN_PASSWORD || process.env.TEST_DB_PASSWORD || 'secret';

process.env.JWT_SECRET              = 'test-jwt-secret-integration';
process.env.ACCESS_TOKEN_EXPIRES_IN = '15m';
process.env.APP_URL                 = 'http://localhost:3000';

// Redis no disponible en tests — el middleware authenticate hace fail-open si Redis falla
process.env.REDIS_URL = 'redis://localhost:9999';
