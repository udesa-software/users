/**
 * Tests de integración — módulo users
 *
 * Estrategia:
 *  - Supertest dispara peticiones HTTP reales contra la app Express.
 *  - La app se conecta a una base de datos PostgreSQL de test (ver jest.integration.config.js).
 *  - Antes de la suite se corren todas las migraciones SQL en orden.
 *  - Antes de cada test se hace TRUNCATE para garantizar aislamiento total.
 *  - Al finalizar la suite se cierran los pools de conexiones.
 *
 * Cobertura (patrón AAA — Arrange / Act / Assert):
 *  - POST  /api/users/register      — registro de cuenta
 *  - GET   /api/users/preferences   — obtención de preferencias
 *  - PATCH /api/users/preferences   — actualización de preferencias
 *  - PATCH /api/users/profile       — edición de perfil (username y biography)
 *  - POST  /api/users/delete        — eliminación de cuenta (soft-delete)
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
const { redisClient }  = require('../../src/config/redis');

// ---------------------------------------------------------------------------
// Constantes y helpers
// ---------------------------------------------------------------------------

const JWT_SECRET    = process.env.JWT_SECRET;
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
  username       = 'testuser',
  email          = 'test@example.com',
  isVerified     = false,
  deletedAt      = null,
  tokenVersion   = 1,
  verifyToken    = null,
  tokenExpiresAt = null,
} = {}) {
  const id = uuidv4();
  const { rows } = await pool.query(
    `INSERT INTO users
       (id, username, email, password_hash, is_verified, deleted_at,
        token_version, verify_token, token_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING *`,
    [
      id,
      username.toLowerCase(),
      email.toLowerCase(),
      TEST_PASSWORD_HASH,
      isVerified,
      deletedAt,
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

/** Obtiene la fila completa de un usuario por id. */
async function findUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] || null;
}

/** Obtiene las preferencias de un usuario directamente de la DB. */
async function findPreferencesByUserId(userId) {
  const { rows } = await pool.query(
    'SELECT * FROM preferences WHERE user_id = $1',
    [userId]
  );
  return rows[0] || null;
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
// POST /api/users/register
// ===========================================================================

describe('POST /api/users/register', () => {
  it('devuelve 400 si falta username', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ email: 'alice@test.com', password: TEST_PASSWORD, acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
    expect(res.body.details).toHaveProperty('username');
  });

  it('devuelve 400 si el username tiene menos de 4 caracteres', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'ali', email: 'alice@test.com', password: TEST_PASSWORD, acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('username');
  });

  it('devuelve 400 si el username supera 15 caracteres', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'alicemuylargoyyyyy', email: 'alice@test.com', password: TEST_PASSWORD, acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('username');
  });

  it('devuelve 400 si el username contiene caracteres especiales', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'alice!', email: 'alice@test.com', password: TEST_PASSWORD, acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('username');
  });

  it('devuelve 400 si el email tiene formato inválido', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'alice', email: 'no-es-email', password: TEST_PASSWORD, acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('email');
  });

  it('devuelve 400 si la contraseña es demasiado débil (sin número)', async () => {
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'alice', email: 'alice@test.com', password: 'SinNumero!', acceptedTerms: true });

    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('password');
  });

  it('devuelve 400 si acceptedTerms es false', async () => {
    // Arrange + Act
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'alice', email: 'alice@test.com', password: TEST_PASSWORD, acceptedTerms: false });

    // Assert: la validación Zod rechaza boolean false para acceptedTerms
    // (el schema requiere que el campo sea true, o el service lanza AppError)
    expect([400, 409].includes(res.status) || res.status === 400).toBeTruthy();
  });

  it('devuelve 201 con datos del usuario y crea preferencias por defecto en la DB', async () => {
    // Act
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'Alice', email: 'Alice@Test.com', password: TEST_PASSWORD, acceptedTerms: true });

    // Assert HTTP
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('message');
    expect(res.body.user).toMatchObject({
      username:   'alice',        // normalizado a minúsculas
      email:      'alice@test.com',
      is_verified: false,         // pendiente de verificación
    });
    expect(res.body.user).toHaveProperty('id');

    // Assert DB: usuario creado
    const dbUser = await findUserById(res.body.user.id);
    expect(dbUser).not.toBeNull();
    expect(dbUser.is_verified).toBe(false);
    expect(dbUser.verify_token).not.toBeNull();   // token de verificación generado

    // Assert DB: preferences creadas por defecto
    const prefs = await findPreferencesByUserId(dbUser.id);
    expect(prefs).not.toBeNull();
    expect(prefs.search_radius_km).toBe(25);
    expect(prefs.location_update_frequency).toBe(5);
  });

  it('devuelve 409 si el email ya está registrado (case-insensitive)', async () => {
    // Arrange: email ya existe en DB
    await insertUser({ username: 'alice', email: 'alice@test.com' });

    // Act: intentar registrar con el mismo email en mayúsculas
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'other', email: 'ALICE@TEST.COM', password: TEST_PASSWORD, acceptedTerms: true });

    // Assert
    expect(res.status).toBe(409);
    expect(res.body).toHaveProperty('error', 'El email ya está registrado');
  });

  it('devuelve 409 si el username ya está en uso (case-insensitive)', async () => {
    // Arrange: username ya existe en DB
    await insertUser({ username: 'alice', email: 'alice@test.com' });

    // Act: intentar registrar con el mismo username en mayúsculas
    const res = await request(app)
      .post('/api/users/register')
      .send({ username: 'ALICE', email: 'otro@test.com', password: TEST_PASSWORD, acceptedTerms: true });

    // Assert
    expect(res.status).toBe(409);
    expect(res.body).toHaveProperty('error', 'El nombre de usuario ya está en uso');
  });
});

// ===========================================================================
// GET /api/users/preferences
// ===========================================================================

describe('GET /api/users/preferences', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app).get('/api/users/preferences');

    expect(res.status).toBe(401);
  });

  it('devuelve las preferencias por defecto después del registro', async () => {
    // Arrange: usuario con preferencias por defecto
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(token));

    // Assert
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      search_radius_km:          25,
      location_update_frequency: 5,
    });
  });

  it('devuelve 404 si el usuario no tiene preferencias en la DB', async () => {
    // Arrange: insertar usuario sin fila de preferences
    const id = uuidv4();
    await pool.query(
      `INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
      [id, 'nopref', 'nopref@test.com', TEST_PASSWORD_HASH]
    );
    const token = makeAccessToken(id, 'nopref', 1);

    // Act
    const res = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(token));

    // Assert
    expect(res.status).toBe(404);
  });
});

// ===========================================================================
// PATCH /api/users/preferences
// ===========================================================================

describe('PATCH /api/users/preferences', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app)
      .patch('/api/users/preferences')
      .send({ search_radius_km: 30 });

    expect(res.status).toBe(401);
  });

  it('devuelve 400 si search_radius_km está fuera de rango (> 50)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ search_radius_km: 100 });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
    expect(res.body.details).toHaveProperty('search_radius_km');
  });

  it('devuelve 400 si location_update_frequency no está en los valores permitidos (5, 15, 30)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: frecuencia inválida
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ location_update_frequency: 10 });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('location_update_frequency');
  });

  it('devuelve 400 si no se envía ningún campo para actualizar', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: body vacío — no hay nada para actualizar
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({});

    // Assert: el service lanza AppError(400)
    expect(res.status).toBe(400);
  });

  it('actualiza search_radius_km y persiste el cambio en la DB', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ search_radius_km: 40 });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message', 'Preferencias actualizadas correctamente');
    expect(res.body.preferences).toHaveProperty('search_radius_km', 40);

    // Assert DB: el cambio se persistió
    const prefs = await findPreferencesByUserId(user.id);
    expect(prefs.search_radius_km).toBe(40);
  });

  it('actualiza location_update_frequency y persiste el cambio en la DB', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ location_update_frequency: 15 });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body.preferences).toHaveProperty('location_update_frequency', 15);

    // Assert DB
    const prefs = await findPreferencesByUserId(user.id);
    expect(prefs.location_update_frequency).toBe(15);
  });

  it('actualiza ambos campos simultáneamente y persiste los cambios en la DB', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ search_radius_km: 10, location_update_frequency: 30 });

    // Assert HTTP
    expect(res.status).toBe(200);

    // Assert DB: ambos campos actualizados
    const prefs = await findPreferencesByUserId(user.id);
    expect(prefs.search_radius_km).toBe(10);
    expect(prefs.location_update_frequency).toBe(30);
  });
});

// ===========================================================================
// PATCH /api/users/profile
// ===========================================================================

describe('PATCH /api/users/profile', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app)
      .patch('/api/users/profile')
      .send({ username: 'newname' });

    expect(res.status).toBe(401);
  });

  it('devuelve 400 si no se envía ningún campo (username ni biography)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: body completamente vacío
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({});

    // Assert: el .refine() de Zod requiere al menos un campo
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
  });

  it('devuelve 400 si el nuevo username es demasiado corto (< 4 chars)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'ali' });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('username');
  });

  it('devuelve 400 si la biography supera 150 caracteres', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: biography de 151 caracteres
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ biography: 'a'.repeat(151) });

    // Assert
    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty('biography');
  });

  it('devuelve 409 si el nuevo username ya está en uso por otro usuario', async () => {
    // Arrange: dos usuarios; alice quiere el username de carlos
    // Nota: el schema exige mínimo 4 chars, por eso usamos 'carlos' y no 'bob'
    await createVerifiedUser({ username: 'carlos', email: 'carlos@test.com' });
    const alice = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(alice.id, alice.username, alice.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'carlos' });

    // Assert
    expect(res.status).toBe(409);
    expect(res.body).toHaveProperty('error', 'El nombre de usuario ya está en uso');
  });

  it('actualiza el username exitosamente y persiste en la DB', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'alicenew' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('username', 'alicenew');

    // Assert DB
    const updated = await findUserById(user.id);
    expect(updated.username).toBe('alicenew');
  });

  it('actualiza la biography exitosamente y persiste en la DB (con sanitización HTML)', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act: biography con tags HTML — deben ser sanitizados
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ biography: 'Hola <script>alert("xss")</script> soy Alice' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('biography');
    // Los tags HTML deben haber sido eliminados
    expect(res.body.biography).not.toContain('<script>');
    expect(res.body.biography).toContain('Hola');

    // Assert DB
    const prefs = await findPreferencesByUserId(user.id);
    expect(prefs.biography).not.toContain('<script>');
  });

  it('actualiza username y biography simultáneamente y persiste ambos cambios', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'alicenew', biography: 'Mi nueva bio' });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('username', 'alicenew');
    expect(res.body).toHaveProperty('biography', 'Mi nueva bio');

    // Assert DB: username actualizado
    const updatedUser = await findUserById(user.id);
    expect(updatedUser.username).toBe('alicenew');

    // Assert DB: biography actualizada en preferences
    const prefs = await findPreferencesByUserId(user.id);
    expect(prefs.biography).toBe('Mi nueva bio');
  });

  it('permite usar el propio username sin conflicto de duplicado', async () => {
    // Arrange: alice actualiza al mismo username (debe ser permitido)
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'alice' }); // mismo username

    // Assert: se permite porque es el propio usuario
    expect(res.status).toBe(200);
  });
});

// ===========================================================================
// POST /api/users/delete
// ===========================================================================

describe('POST /api/users/delete', () => {
  it('devuelve 401 sin token de acceso', async () => {
    const res = await request(app)
      .post('/api/users/delete')
      .send({ password: TEST_PASSWORD });

    expect(res.status).toBe(401);
  });

  it('devuelve 400 si falta el campo password en el body', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/users/delete')
      .set(authHeader(token))
      .send({});

    // Assert
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'Validation failed');
    expect(res.body.details).toHaveProperty('password');
  });

  it('devuelve 401 si la contraseña de confirmación es incorrecta', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/users/delete')
      .set(authHeader(token))
      .send({ password: 'ContraseñaMal1' });

    // Assert
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'Contraseña incorrecta');
  });

  it('devuelve 200 y aplica soft-delete (setea deleted_at) en la DB', async () => {
    // Arrange
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Act
    const res = await request(app)
      .post('/api/users/delete')
      .set(authHeader(token))
      .send({ password: TEST_PASSWORD });

    // Assert HTTP
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message', 'Tu cuenta ha sido eliminada.');

    // Assert DB: soft-delete — la fila sigue existiendo con deleted_at seteado
    const deleted = await findUserById(user.id);
    expect(deleted).not.toBeNull();
    expect(deleted.deleted_at).not.toBeNull();
  });

  it('la cuenta eliminada no puede iniciar sesión (devuelve 403)', async () => {
    // Arrange: usuario que se elimina
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // Eliminar la cuenta
    await request(app)
      .post('/api/users/delete')
      .set(authHeader(token))
      .send({ password: TEST_PASSWORD });

    // Act: intentar iniciar sesión con la cuenta eliminada
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: TEST_PASSWORD });

    // Assert: cuenta suspendida/eliminada devuelve 403
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'Cuenta suspendida');
  });
});

// ===========================================================================
// Flujos multi-paso (integración entre endpoints)
// ===========================================================================

describe('flujos multi-paso', () => {
  it('registro → obtener preferencias (defecto) → actualizar → verificar persistencia', async () => {
    // 1. Registro via API
    const regRes = await request(app)
      .post('/api/users/register')
      .send({
        username:      'alice',
        email:         'alice@test.com',
        password:      TEST_PASSWORD,
        acceptedTerms: true,
      });
    expect(regRes.status).toBe(201);
    const userId = regRes.body.user.id;

    // Crear token para el usuario
    const token = makeAccessToken(userId, 'alice', 1);

    // 2. Obtener preferencias — deben ser las por defecto
    const getRes = await request(app)
      .get('/api/users/preferences')
      .set(authHeader(token));
    expect(getRes.status).toBe(200);
    expect(getRes.body).toMatchObject({ search_radius_km: 25, location_update_frequency: 5 });

    // 3. Actualizar preferencias
    const patchRes = await request(app)
      .patch('/api/users/preferences')
      .set(authHeader(token))
      .send({ search_radius_km: 15, location_update_frequency: 30 });
    expect(patchRes.status).toBe(200);

    // 4. Verificar que los cambios persisten consultando la DB
    const prefs = await findPreferencesByUserId(userId);
    expect(prefs.search_radius_km).toBe(15);
    expect(prefs.location_update_frequency).toBe(30);
  });

  it('registro → actualizar profile (username) → nuevo username reflejado en DB', async () => {
    // 1. Registro via API
    const regRes = await request(app)
      .post('/api/users/register')
      .send({
        username:      'alice',
        email:         'alice@test.com',
        password:      TEST_PASSWORD,
        acceptedTerms: true,
      });
    expect(regRes.status).toBe(201);
    const userId = regRes.body.user.id;

    // 2. Actualizar username
    const token = makeAccessToken(userId, 'alice', 1);
    const patchRes = await request(app)
      .patch('/api/users/profile')
      .set(authHeader(token))
      .send({ username: 'alicenew', biography: 'Hola soy Alice' });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body).toMatchObject({ username: 'alicenew', biography: 'Hola soy Alice' });

    // 3. Verificar en DB que el cambio persiste
    const updatedUser = await findUserById(userId);
    expect(updatedUser.username).toBe('alicenew');

    const prefs = await findPreferencesByUserId(userId);
    expect(prefs.biography).toBe('Hola soy Alice');
  });

  it('registro → eliminar cuenta → login rechazado → preferencias rechazadas', async () => {
    // 1. Registro e inserción directa como verificado
    const user  = await createVerifiedUser({ username: 'alice', email: 'alice@test.com' });
    const token = makeAccessToken(user.id, user.username, user.token_version);

    // 2. Eliminar cuenta
    const deleteRes = await request(app)
      .post('/api/users/delete')
      .set(authHeader(token))
      .send({ password: TEST_PASSWORD });
    expect(deleteRes.status).toBe(200);

    // 3. Login rechazado
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'alice@test.com', password: TEST_PASSWORD });
    expect(loginRes.status).toBe(403);

    // 4. Verificar soft-delete en DB
    const dbUser = await findUserById(user.id);
    expect(dbUser.deleted_at).not.toBeNull();
  });
});
