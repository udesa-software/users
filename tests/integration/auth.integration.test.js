/**
 * Tests de integración — módulo auth
 *
 * Estrategia:
 *  - Supertest dispara peticiones HTTP reales contra la app Express.
 *  - La app se conecta a una base de datos PostgreSQL de test (ver jest.integration.config.js).
 *  - Antes de la suite se corren todas las migraciones SQL en orden.
 *  - Antes de cada test se hace TRUNCATE para garantizar aislamiento total.
 *  - Al finalizar la suite se cierran los pools de conexiones.
 *
 * Cobertura (patrón AAA — Arrange / Act / Assert):
 *  - Middleware authenticate (401 con y sin token)
 *  - POST /api/auth/login           — login por email y username
 *  - POST /api/auth/refresh         — rotación de refresh token
 *  - POST /api/auth/logout          — cierre de sesión
 *  - POST /api/auth/change-password — cambio de contraseña autenticado
 *  - GET  /api/auth/verify-email    — verificación de cuenta
 *  - POST /api/auth/resend-verification — reenvío de email
 *  - POST /api/auth/forgot-password — solicitud de reset
 *  - POST /api/auth/reset-password  — restablecimiento con token
 *  - GET  /api/auth/reset-password  — validación de token (devuelve HTML)
 *  - Flujos multi-paso que cruzan varios endpoints
 */

const request  = require('supertest');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs       = require('fs');
const path     = require('path');

// setupFiles ya seteó process.env antes de este require
const app              = require('../../src/app');
const { pool, migrationPool } = require('../../src/config/database');
const { hashToken }    = require('../../src/utils/tokenHash');
const { redisClient }  = require('../../src/config/redis');

// ---------------------------------------------------------------------------
// Constantes y helpers
// ---------------------------------------------------------------------------

const JWT_SECRET   = process.env.JWT_SECRET;
const TEST_PASSWORD = 'Test1234!';
let   TEST_PASSWORD_HASH; // se calcula en beforeAll con cost bajo para velocidad

/** Genera un JWT de acceso válido para tests. */
function makeAccessToken(userId, username, tokenVersion = 1) {
  return jwt.sign(
    { sub: userId, username, token_version: tokenVersion, type: 'access' },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

/** Header Authorization listo para pasarle a supertest. */
function authHeader(token) {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Inserta directamente en la DB un usuario con el estado indicado.
 * Crea también la fila de preferences por defecto.
 */
async function insertUser({
  username        = 'testuser',
  email           = 'test@example.com',
  isVerified      = false,
  deletedAt       = null,
  isSuspended     = false,
  failedLoginAttempts = 0,
  lockedUntil     = null,
  tokenVersion    = 1,
  verifyToken     = null,
  tokenExpiresAt  = null,
} = {}) {
  const id = uuidv4();
  const { rows } = await pool.query(
    `INSERT INTO users
       (id, username, email, password_hash, is_verified, deleted_at, is_suspended,
        failed_login_attempts, locked_until, token_version, verify_token, token_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
     RETURNING *`,
    [
      id,
      username.toLowerCase(),
      email.toLowerCase(),
      TEST_PASSWORD_HASH,
      isVerified,
      deletedAt,
      isSuspended,
      failedLoginAttempts,
      lockedUntil,
      tokenVersion,
      verifyToken,
      tokenExpiresAt,
    ]
  );
  const user = rows[0];

  // Crear preferences por defecto (igual que hace userService.register)
  await pool.query('INSERT INTO preferences (user_id) VALUES ($1)', [user.id]);

  return user;
}

/** Inserta un refresh token en la DB y devuelve el token opaco (antes de hashear). */
async function insertRefreshToken(userId, token = uuidv4()) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 días
  await pool.query(
    'INSERT INTO user_refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, hashToken(token), expiresAt]
  );
  return token;
}

/** Obtiene la fila completa de un usuario por id. */
async function findUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] || null;
}

/** Cuenta los refresh tokens activos de un usuario en la DB. */
async function countRefreshTokens(userId) {
  const { rows } = await pool.query(
    'SELECT COUNT(*) AS cnt FROM user_refresh_tokens WHERE user_id = $1',
    [userId]
  );
  return parseInt(rows[0].cnt, 10);
}

/** Crea un usuario verificado listo para usar en tests. */
async function createVerifiedUser(overrides = {}) {
  return insertUser({ ...overrides, isVerified: true });
}

// ---------------------------------------------------------------------------
// Setup / teardown de la suite
// ---------------------------------------------------------------------------

beforeAll(async () => {
  // Cost 1 para que los tests corran rápido (bcrypt.compare sigue funcionando igual)
  TEST_PASSWORD_HASH = await bcrypt.hash(TEST_PASSWORD, 1);

  // Ejecuta todas las migraciones SQL en orden numérico.
  // IF NOT EXISTS garantiza idempotencia si la DB ya tiene el esquema.
  const migrationsDir = path.join(__dirname, '../../src/db/migrations');
  const files = fs.readdirSync(migrationsDir).sort();
  for (const file of files) {
    if (!file.endsWith('.sql')) continue;
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    await migrationPool.query(sql);
  }
});

beforeEach(async () => {
  // Limpia todas las tablas antes de cada test para garantizar aislamiento.
  // CASCADE propaga el truncate a las tablas que referencian a users.
  await pool.query(
    'TRUNCATE TABLE user_refresh_tokens, preferences, users RESTART IDENTITY CASCADE'
  );
});

afterAll(async () => {
  // Desconectar Redis antes de cerrar los pools para evitar logs post-suite
  redisClient.disconnect();
  await pool.end();
  await migrationPool.end();
});

// ===========================================================================
// MIDDLEWARE authenticate
// ===========================================================================

describe('authenticate middleware', () => {
  it('devuelve 401 cuando no se envía token', async () => {
    // Arrange: no Authorization header
    // Act
    const res = await request(app).get('/api/users/preferences');
    // Assert
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 401 cuando el token está malformado', async () => {
    const res = await request(app)
      .get('/api/users/preferences')
      .set('Authorization', 'Bearer token-invalido-xxxx');

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 401 cuando el token fue firmado con otro secreto', async () => {
    // Arrange
    const user = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const tokenConOtroSecreto = jwt.sign(
      { sub: user.id, username: user.username, token_version: 1, type: 'access' },
      'secreto-incorrecto'
    );

    // Act
    const res = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(tokenConOtroSecreto));

    // Assert
    expect(res.status).toBe(401);
  });

  it('permite el acceso con un token válido', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(token));

    // Assert: no es 401 (el middleware lo dejó pasar)
    expect(res.status).not.toBe(401);
  });
});

// ===========================================================================
// POST /api/auth/login
// ===========================================================================

describe('POST /api/auth/login', () => {
  it('devuelve 400 si falta identifier', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ password: TEST_PASSWORD });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 400 si falta password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com' });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 401 si el usuario no existe — mensaje genérico', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'noexiste@test.com', password: TEST_PASSWORD });

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'Credenciales inválidas');
  });

  it('devuelve 403 si la cuenta no está verificada', async () => {
    // Arrange: usuario sin verificar
    await insertUser({ username: 'unverified', email: 'unverified@test.com', isVerified: false });

    // Act
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'unverified@test.com', password: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 403 si la cuenta fue eliminada (soft-delete)', async () => {
    // Arrange: usuario con deleted_at seteado
    await insertUser({
      username:  'deleted',
      email:     'deleted@test.com',
      isVerified: true,
      deletedAt: new Date(),
    });

    // Act
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'deleted@test.com', password: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'Cuenta suspendida');
  });

  it('devuelve 401 si la contraseña es incorrecta — mensaje genérico', async () => {
    // Arrange
    await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: 'ContraseñaMal1' });

    // Assert: mismo mensaje que "usuario no existe" para no revelar existencia
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'Credenciales inválidas');
  });

  it('devuelve 200, accessToken, refreshToken y datos del usuario en login exitoso por email', async () => {
    // Arrange
    await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: TEST_PASSWORD });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body.user).toMatchObject({ username: 'alice', email: 'alice@test.com', is_verified: true });

    // Assert DB: el refresh token se guardó en la tabla
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', ['alice@test.com']);
    const count = await countRefreshTokens(rows[0].id);
    expect(count).toBe(1);
  });

  it('devuelve 200 en login exitoso por username (case-insensitive)', async () => {
    // Arrange
    await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act: login con username en mayúsculas
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'ALICE', password: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(200);
    expect(res.body.user.username).toBe('alice');
  });

  it('devuelve 423 cuando la cuenta ya está bloqueada por intentos fallidos previos', async () => {
    // Arrange: cuenta bloqueada con locked_until en el futuro
    const lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
    await insertUser({
      username:   'locked',
      email:      'locked@test.com',
      isVerified: true,
      failedLoginAttempts: 5,
      lockedUntil,
    });

    // Act
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'locked@test.com', password: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(423);
    expect(res.body).toHaveProperty('error');
  });

  it('bloquea la cuenta automáticamente después de 5 intentos fallidos consecutivos', async () => {
    // Arrange
    await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act: 5 intentos con contraseña incorrecta
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ identifier: 'alice@test.com', password: 'ContraseñaMal1' });
    }

    // El 6to intento (aunque sea con contraseña correcta) devuelve 423
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: TEST_PASSWORD });

    // Assert HTTP
    expect(res.status).toBe(423);

    // Assert DB: locked_until fue seteado
    const { rows } = await pool.query(
      'SELECT locked_until FROM users WHERE email = $1',
      ['alice@test.com']
    );
    expect(rows[0].locked_until).not.toBeNull();
  });
});

// ===========================================================================
// POST /api/auth/refresh
// ===========================================================================

describe('POST /api/auth/refresh', () => {
  it('devuelve 401 si no se envía refreshToken en el body', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({});

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'Refresh token requerido');
  });

  it('devuelve 401 si el refreshToken no existe en la DB', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: uuidv4() });

    expect(res.status).toBe(401);
  });

  it('devuelve 200 con nuevo accessToken y rota el refreshToken', async () => {
    // Arrange
    const user     = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const oldToken = await insertRefreshToken(user.id);

    // Act
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: oldToken });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body.refreshToken).not.toBe(oldToken); // token rotado

    // Assert DB: el token viejo ya no existe; el nuevo sí
    const { rows: oldRows } = await pool.query(
      'SELECT * FROM user_refresh_tokens WHERE token_hash = $1',
      [hashToken(oldToken)]
    );
    expect(oldRows).toHaveLength(0);

    const { rows: newRows } = await pool.query(
      'SELECT * FROM user_refresh_tokens WHERE token_hash = $1',
      [hashToken(res.body.refreshToken)]
    );
    expect(newRows).toHaveLength(1);
  });

  it('rechaza el token viejo después de una rotación — previene reutilización', async () => {
    // Arrange
    const user     = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const oldToken = await insertRefreshToken(user.id);

    // Primera rotación exitosa
    const first = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: oldToken });
    expect(first.status).toBe(200);

    // Act: intentar usar el token viejo de nuevo
    const second = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: oldToken });

    // Assert: ya no es válido
    expect(second.status).toBe(401);
  });

  it('devuelve 403 si el usuario fue suspendido después del login', async () => {
    // Arrange: usuario activo con refresh token
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = await insertRefreshToken(user.id);

    // Suspender al usuario directamente en la DB (simula acción de admin)
    await pool.query('UPDATE users SET is_suspended = TRUE WHERE id = $1', [user.id]);

    // Act
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: token });

    // Assert
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'Cuenta suspendida');
  });
});

// ===========================================================================
// POST /api/auth/logout
// ===========================================================================

describe('POST /api/auth/logout', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app).post('/api/auth/logout');

    expect(res.status).toBe(401);
  });

  it('devuelve 200 y elimina el refreshToken de la DB', async () => {
    // Arrange
    const user         = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const accessToken  = makeAccessToken(user.id, user.username, user.token_version);
    const refreshToken = await insertRefreshToken(user.id);
    expect(await countRefreshTokens(user.id)).toBe(1);

    // Act
    const res = await request(app)
      .post('/api/auth/logout')
      .set(authHeader(accessToken))
      .send({ refreshToken });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');

    // Assert DB: el refresh token fue eliminado
    expect(await countRefreshTokens(user.id)).toBe(0);
  });

  it('después del logout, el refreshToken queda inválido para /refresh', async () => {
    // Arrange
    const user         = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const accessToken  = makeAccessToken(user.id, user.username, user.token_version);
    const refreshToken = await insertRefreshToken(user.id);

    // Logout
    await request(app)
      .post('/api/auth/logout')
      .set(authHeader(accessToken))
      .send({ refreshToken });

    // Act: intentar refrescar con el token eliminado
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken });

    // Assert
    expect(res.status).toBe(401);
  });
});

// ===========================================================================
// POST /api/auth/change-password
// ===========================================================================

describe('POST /api/auth/change-password', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    expect(res.status).toBe(401);
  });

  it('devuelve 400 si falta currentPassword', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ newPassword: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
    expect(res.body.details).toHaveProperty('currentPassword');
  });

  it('devuelve 400 si newPassword y confirmPassword no coinciden (validación Zod)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'NuevaClave1', confirmPassword: 'OtraClave1' });

    // Assert
    expect(res.status).toBe(400);
  });

  it('devuelve 400 si la nueva contraseña es demasiado débil (sin mayúscula)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: contraseña sin mayúscula
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'clavesinmay1', confirmPassword: 'clavesinmay1' });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 401 si la contraseña actual es incorrecta', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: 'ContraseñaMal1', newPassword: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    // Assert
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'La contraseña actual es incorrecta');
  });

  it('devuelve 400 si la nueva contraseña es igual a la actual', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: misma contraseña
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword: TEST_PASSWORD, confirmPassword: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'La nueva contraseña no puede ser igual a la anterior');
  });

  it('devuelve 200 y elimina todos los refreshTokens de la DB (invalida todas las sesiones)', async () => {
    // Arrange: usuario con 2 sesiones activas
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);
    await insertRefreshToken(user.id);
    await insertRefreshToken(user.id);
    expect(await countRefreshTokens(user.id)).toBe(2);

    // Act
    const res = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');

    // Assert DB: todos los refresh tokens eliminados
    expect(await countRefreshTokens(user.id)).toBe(0);
  });

  it('después del cambio se puede iniciar sesión con la nueva contraseña', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: cambiar contraseña
    const newPassword = 'NuevaClave1';
    await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword, confirmPassword: newPassword });

    // Assert: login con nueva contraseña funciona
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: newPassword });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
  });
});

// ===========================================================================
// GET /api/auth/verify-email
// ===========================================================================

describe('GET /api/auth/verify-email', () => {
  it('devuelve 400 si no se envía token', async () => {
    const res = await request(app).get('/api/auth/verify-email');

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 400 si el token no existe en la DB', async () => {
    const res = await request(app)
      .get('/api/auth/verify-email')
      .query({ token: uuidv4() });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 400 si el token expiró', async () => {
    // Arrange: token expirado (token_expires_at en el pasado)
    const expiredToken  = uuidv4();
    const tokenExpiresAt = new Date(Date.now() - 60 * 1000); // hace 1 minuto
    await insertUser({
      username:       'alice',
      email:          'alice@test.com',
      isVerified:     false,
      verifyToken:    expiredToken,
      tokenExpiresAt,
    });

    // Act
    const res = await request(app)
      .get('/api/auth/verify-email')
      .query({ token: expiredToken });

    // Assert: token expirado es inválido
    expect(res.status).toBe(400);
  });

  it('devuelve 200 y marca al usuario como verificado en la DB', async () => {
    // Arrange: token válido no expirado
    const verifyToken    = uuidv4();
    const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
    const user = await insertUser({
      username:       'alice',
      email:          'alice@test.com',
      isVerified:     false,
      verifyToken,
      tokenExpiresAt,
    });

    // Act
    const res = await request(app)
      .get('/api/auth/verify-email')
      .query({ token: verifyToken });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');

    // Assert DB: is_verified = true y verify_token limpiado
    const updated = await findUserById(user.id);
    expect(updated.is_verified).toBe(true);
    expect(updated.verify_token).toBeNull();
    expect(updated.token_expires_at).toBeNull();
  });

  it('devuelve 400 si el token ya fue usado (nullificado en DB)', async () => {
    // Arrange: token válido
    const verifyToken    = uuidv4();
    const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await insertUser({
      username:       'alice',
      email:          'alice@test.com',
      isVerified:     false,
      verifyToken,
      tokenExpiresAt,
    });

    // Primera verificación — exitosa
    await request(app).get('/api/auth/verify-email').query({ token: verifyToken });

    // Act: segunda verificación con el mismo token
    const res = await request(app)
      .get('/api/auth/verify-email')
      .query({ token: verifyToken });

    // Assert: el token ya no existe en DB
    expect(res.status).toBe(400);
  });
});

// ===========================================================================
// POST /api/auth/resend-verification
// ===========================================================================

describe('POST /api/auth/resend-verification', () => {
  it('devuelve 400 si el formato del email es inválido', async () => {
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ email: 'no-es-email' });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
    expect(res.body.details).toHaveProperty('email');
  });

  it('devuelve 404 si el email no está registrado', async () => {
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ email: 'noexiste@test.com' });

    expect(res.status).toBe(404);
  });

  it('devuelve 400 si la cuenta ya está verificada', async () => {
    // Arrange: usuario ya verificado
    await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ email: 'alice@test.com' });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'La cuenta ya fue verificada');
  });

  it('devuelve 200 y actualiza el verify_token en la DB', async () => {
    // Arrange: usuario sin verificar con token viejo
    const oldToken = uuidv4();
    const user = await insertUser({
      username:       'alice',
      email:          'alice@test.com',
      isVerified:     false,
      verifyToken:    oldToken,
      tokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    // Act
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ email: 'alice@test.com' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message', 'Email de verificación reenviado.');

    // Assert DB: el verify_token fue renovado
    const updated = await findUserById(user.id);
    expect(updated.verify_token).not.toBeNull();
    expect(updated.verify_token).not.toBe(oldToken); // token distinto al anterior
  });
});

// ===========================================================================
// POST /api/auth/forgot-password
// ===========================================================================

describe('POST /api/auth/forgot-password', () => {
  it('devuelve 400 si falta identifier', async () => {
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({});

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 200 (respuesta genérica) si el usuario no existe — evita enumeración', async () => {
    // Act: email que no existe en la DB
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ identifier: 'noexiste@test.com' });

    // Assert: 200 genérico para no revelar si el email existe
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');
  });

  it('devuelve 200 y persiste el password_reset_token en la DB cuando el usuario existe', async () => {
    // Arrange
    const user = await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });

    // Act
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ identifier: 'alice@test.com' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');

    // Assert DB: el reset token fue guardado con expiración
    const updated = await findUserById(user.id);
    expect(updated.password_reset_token).not.toBeNull();
    expect(updated.password_reset_expires_at).not.toBeNull();
    expect(new Date(updated.password_reset_expires_at) > new Date()).toBe(true);
  });
});

// ===========================================================================
// POST /api/auth/reset-password
// ===========================================================================

describe('POST /api/auth/reset-password', () => {
  it('devuelve 400 si el token no tiene formato UUID', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: 'no-es-uuid', password: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 400 si el token no existe en la DB', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: uuidv4(), password: 'NuevaClave1', confirmPassword: 'NuevaClave1' });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('devuelve 400 si las contraseñas no coinciden', async () => {
    // Arrange: insertar reset token válido
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com' });
    const expiresAt  = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act: contraseñas distintas
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: 'NuevaClave1', confirmPassword: 'OtraClave1' });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Las contraseñas no coinciden');
  });

  it('devuelve 400 si la nueva contraseña es igual a la actual', async () => {
    // Arrange
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com' });
    const expiresAt  = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act: misma contraseña que la actual
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: TEST_PASSWORD, confirmPassword: TEST_PASSWORD });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'La nueva contraseña no puede ser igual a la anterior');
  });

  it('devuelve 200 y limpia el reset token en la DB', async () => {
    // Arrange
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });
    const expiresAt  = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act
    const newPassword = 'NuevaClave1';
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword, confirmPassword: newPassword });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');

    // Assert DB: reset token fue limpiado
    const updated = await findUserById(user.id);
    expect(updated.password_reset_token).toBeNull();
    expect(updated.password_reset_expires_at).toBeNull();
  });

  it('invalida todos los refreshTokens existentes al resetear la contraseña', async () => {
    // Arrange: usuario con sesiones activas
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });
    await insertRefreshToken(user.id);
    await insertRefreshToken(user.id);
    expect(await countRefreshTokens(user.id)).toBe(2);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act
    const newPassword = 'NuevaClave1';
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword, confirmPassword: newPassword });

    // Assert DB: todos los refresh tokens eliminados
    expect(await countRefreshTokens(user.id)).toBe(0);
  });

  it('después del reset se puede iniciar sesión con la nueva contraseña', async () => {
    // Arrange
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com', isVerified: true });
    const expiresAt  = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act: resetear contraseña
    const newPassword = 'NuevaClave1';
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword, confirmPassword: newPassword });

    // Assert: login con nueva contraseña exitoso
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: newPassword });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body).toHaveProperty('accessToken');
  });
});

// ===========================================================================
// GET /api/auth/reset-password — verifyResetToken (devuelve HTML)
// ===========================================================================

describe('GET /api/auth/reset-password', () => {
  it('devuelve 400 (HTML) con token inválido o inexistente', async () => {
    const res = await request(app)
      .get('/api/auth/reset-password')
      .query({ token: uuidv4() });

    expect(res.status).toBe(400);
  });

  it('devuelve 200 (HTML) con token válido — contiene el deep link para la app', async () => {
    // Arrange
    const resetToken = uuidv4();
    const user       = await insertUser({ username: 'alice', email: 'alice@test.com' });
    const expiresAt  = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [resetToken, expiresAt, user.id]
    );

    // Act
    const res = await request(app)
      .get('/api/auth/reset-password')
      .query({ token: resetToken });

    // Assert
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toMatch(/html/);
    expect(res.text).toContain(resetToken); // el HTML referencia el token
  });
});

// ===========================================================================
// Flujos multi-paso (integración entre endpoints)
// ===========================================================================

describe('flujos multi-paso', () => {
  it('flujo completo: registro → login sin verificar (403) → verificar email → login exitoso → ruta protegida', async () => {
    // 1. Registro
    const regRes = await request(app)
      .post('/api/users/register')
      .send({
        username:      'newuser',
        email:         'newuser@test.com',
        password:      TEST_PASSWORD,
        acceptedTerms: true,
      });
    expect(regRes.status).toBe(201);

    // 2. Login sin verificar — debe fallar con 403
    const loginFail = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'newuser@test.com', password: TEST_PASSWORD });
    expect(loginFail.status).toBe(403);

    // 3. Obtener verify_token directamente de la DB
    const { rows } = await pool.query(
      'SELECT verify_token FROM users WHERE email = $1',
      ['newuser@test.com']
    );
    const verifyToken = rows[0].verify_token;
    expect(verifyToken).not.toBeNull();

    // 4. Verificar email
    const verifyRes = await request(app)
      .get('/api/auth/verify-email')
      .query({ token: verifyToken });
    expect(verifyRes.status).toBe(200);

    // 5. Login con cuenta verificada — ahora funciona
    const loginOk = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'newuser@test.com', password: TEST_PASSWORD });
    expect(loginOk.status).toBe(200);
    expect(loginOk.body).toHaveProperty('accessToken');

    // 6. Acceder a ruta protegida con el access token obtenido
    const protectedRes = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(loginOk.body.accessToken));
    expect(protectedRes.status).toBe(200);
  });

  it('flujo: login → logout → refresh token queda inválido', async () => {
    // Arrange: usuario verificado con refresh token
    const user         = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const accessToken  = makeAccessToken(user.id, user.username, user.token_version);
    const refreshToken = await insertRefreshToken(user.id);

    // Logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set(authHeader(accessToken))
      .send({ refreshToken });
    expect(logoutRes.status).toBe(200);

    // Act: intentar refrescar después del logout
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken });

    // Assert: token ya no es válido en DB
    expect(refreshRes.status).toBe(401);
  });

  it('flujo: forgot password → reset password → login con nueva contraseña → vieja contraseña rechazada', async () => {
    // Arrange
    const user = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });

    // Solicitar reset
    await request(app)
      .post('/api/auth/forgot-password')
      .send({ identifier: 'alice@test.com' });

    // Obtener reset token de la DB
    const { rows } = await pool.query(
      'SELECT password_reset_token FROM users WHERE id = $1',
      [user.id]
    );
    const resetToken = rows[0].password_reset_token;

    // Resetear contraseña
    const newPassword = 'NuevaClave1';
    const resetRes = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword, confirmPassword: newPassword });
    expect(resetRes.status).toBe(200);

    // Act 1: login con nueva contraseña — exitoso
    const loginNewPass = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: newPassword });
    expect(loginNewPass.status).toBe(200);

    // Act 2: login con contraseña vieja — rechazado
    const loginOldPass = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: TEST_PASSWORD });
    expect(loginOldPass.status).toBe(401);
  });

  it('flujo: change password → refresh tokens anteriores eliminados de la DB', async () => {
    // Arrange: usuario con múltiples sesiones activas
    const user        = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const accessToken = makeAccessToken(user.id, user.username, user.token_version);

    // Simular 3 sesiones activas (dispositivos distintos)
    const token1 = await insertRefreshToken(user.id);
    const token2 = await insertRefreshToken(user.id);
    await insertRefreshToken(user.id);
    expect(await countRefreshTokens(user.id)).toBe(3);

    // Cambiar contraseña
    const newPassword = 'NuevaClave1';
    const changeRes = await request(app)
      .post('/api/auth/change-password')
      .set(authHeader(accessToken))
      .send({ currentPassword: TEST_PASSWORD, newPassword, confirmPassword: newPassword });
    expect(changeRes.status).toBe(200);

    // Assert: todos los refresh tokens eliminados
    expect(await countRefreshTokens(user.id)).toBe(0);

    // Los tokens anteriores no sirven para refrescar
    const refresh1 = await request(app).post('/api/auth/refresh').send({ refreshToken: token1 });
    const refresh2 = await request(app).post('/api/auth/refresh').send({ refreshToken: token2 });
    expect(refresh1.status).toBe(401);
    expect(refresh2.status).toBe(401);
  });
});
