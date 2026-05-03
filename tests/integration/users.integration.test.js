const request = require('supertest');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = require('../../src/app');
const { pool, migrationPool } = require('../../src/config/database');

// ─── Migration runner ────────────────────────────────────────────────────────

async function runMigrations() {
  const dir = path.join(__dirname, '../../src/db/migrations');
  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.sql') || f.endsWith('.js'))
    .sort();

  for (const file of files) {
    const filePath = path.join(dir, file);
    if (file.endsWith('.sql')) {
      const sql = fs.readFileSync(filePath, 'utf-8');
      await migrationPool.query(sql);
    } else {
      const migration = require(filePath);
      await migration(migrationPool);
    }
  }
}

// ─── DB helpers ─────────────────────────────────────────────────────────────

async function truncateTables() {
  await pool.query(
    'TRUNCATE TABLE users RESTART IDENTITY CASCADE'
  );
}

async function insertVerifiedUser({
  username = 'testuser',
  email = 'test@example.com',
  password = 'Password1',
  isVerified = true,
  isSuspended = false,
  deletedAt = null,
  role = 'user',
} = {}) {
  const passwordHash = await bcrypt.hash(password, 1);
  const result = await pool.query(
    `INSERT INTO users
       (username, email, password_hash, is_verified, is_suspended, deleted_at, role_)
     VALUES (LOWER($1), LOWER($2), $3, $4, $5, $6, $7)
     RETURNING id, username, email, token_version`,
    [username, email, passwordHash, isVerified, isSuspended, deletedAt, role]
  );
  const user = result.rows[0];
  await pool.query('INSERT INTO preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [user.id]);
  return user;
}

async function insertUnverifiedUser({ username = 'unverified', email = 'unverified@example.com', password = 'Password1' } = {}) {
  const passwordHash = await bcrypt.hash(password, 1);
  const verifyToken = uuidv4();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const result = await pool.query(
    `INSERT INTO users
       (username, email, password_hash, is_verified, verify_token, token_expires_at)
     VALUES (LOWER($1), LOWER($2), $3, FALSE, $4, $5)
     RETURNING id, username, email, verify_token`,
    [username, email, passwordHash, verifyToken, expiresAt]
  );
  await pool.query('INSERT INTO preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [result.rows[0].id]);
  return result.rows[0];
}

// ─── JWT helper ─────────────────────────────────────────────────────────────

function makeToken(user, overrides = {}) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      email: user.email,
      token_version: user.token_version ?? 1,
      type: 'access',
      ...overrides,
    },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
}

// ─── Setup / teardown ───────────────────────────────────────────────────────

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateTables();
});

afterAll(async () => {
  await pool.end();
  await migrationPool.end();
});

// ════════════════════════════════════════════════════════════════════════════
// Health
// ════════════════════════════════════════════════════════════════════════════

describe('GET /health', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// authenticate middleware
// ════════════════════════════════════════════════════════════════════════════

describe('authenticate middleware', () => {
  it('401 when no Authorization header', async () => {
    const res = await request(app).get('/api/users/preferences');
    expect(res.status).toBe(401);
  });

  it('401 when token is malformed', async () => {
    const res = await request(app)
      .get('/api/users/preferences')
      .set('Authorization', 'Bearer not-a-token');
    expect(res.status).toBe(401);
  });

  it('401 when token signed with wrong secret', async () => {
    const user = await insertVerifiedUser();
    const badToken = jwt.sign({ sub: user.id, token_version: 1, type: 'access' }, 'wrong-secret', { expiresIn: '15m' });
    const res = await request(app)
      .get('/api/users/preferences')
      .set('Authorization', `Bearer ${badToken}`);
    expect(res.status).toBe(401);
  });

  it('passes through with valid token', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .get('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/users/register
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/users/register', () => {
  const validPayload = {
    username: 'newuser1',
    email: 'newuser@example.com',
    password: 'Password1',
    acceptedTerms: true,
  };

  it('201 — creates user and default preferences', async () => {
    const res = await request(app).post('/api/users/register').send(validPayload);
    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe('newuser@example.com');
    expect(res.body.user.is_verified).toBe(false);

    const dbUser = await pool.query('SELECT * FROM users WHERE email = $1', ['newuser@example.com']);
    expect(dbUser.rows).toHaveLength(1);

    const prefs = await pool.query('SELECT * FROM preferences WHERE user_id = $1', [dbUser.rows[0].id]);
    expect(prefs.rows).toHaveLength(1);
    expect(prefs.rows[0].search_radius_km).toBe(25);
  });

  it('409 — duplicate email (case-insensitive)', async () => {
    await insertVerifiedUser({ email: 'newuser@example.com' });
    const res = await request(app).post('/api/users/register').send({ ...validPayload, email: 'NEWUSER@example.com' });
    expect(res.status).toBe(409);
  });

  it('409 — duplicate username', async () => {
    await insertVerifiedUser({ username: 'newuser1' });
    const res = await request(app).post('/api/users/register').send(validPayload);
    expect(res.status).toBe(409);
  });

  it('400 — acceptedTerms is false', async () => {
    const res = await request(app).post('/api/users/register').send({ ...validPayload, acceptedTerms: false });
    expect(res.status).toBe(400);
  });

  it('400 — password too short', async () => {
    const res = await request(app).post('/api/users/register').send({ ...validPayload, password: 'short' });
    expect(res.status).toBe(400);
  });

  it('400 — password without uppercase', async () => {
    const res = await request(app).post('/api/users/register').send({ ...validPayload, password: 'password1' });
    expect(res.status).toBe(400);
  });

  it('400 — username too short', async () => {
    const res = await request(app).post('/api/users/register').send({ ...validPayload, username: 'ab' });
    expect(res.status).toBe(400);
  });

  it('400 — username with special characters', async () => {
    const res = await request(app).post('/api/users/register').send({ ...validPayload, username: 'bad-user!' });
    expect(res.status).toBe(400);
  });

  it('stores username in lowercase', async () => {
    await request(app).post('/api/users/register').send({ ...validPayload, username: 'NewUser1', email: 'lower@example.com' });
    const dbUser = await pool.query('SELECT username FROM users WHERE email = $1', ['lower@example.com']);
    expect(dbUser.rows[0].username).toBe('newuser1');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/auth/verify-email
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/auth/verify-email', () => {
  it('200 — verifies user and marks is_verified=true', async () => {
    const user = await insertUnverifiedUser();
    const res = await request(app).get(`/api/auth/verify-email?token=${user.verify_token}`);
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT is_verified FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].is_verified).toBe(true);
  });

  it('400 — invalid token', async () => {
    const res = await request(app).get(`/api/auth/verify-email?token=${uuidv4()}`);
    expect(res.status).toBe(400);
  });

  it('400 — expired token', async () => {
    const passwordHash = await bcrypt.hash('Password1', 1);
    const expiredToken = uuidv4();
    await pool.query(
      `INSERT INTO users (username, email, password_hash, is_verified, verify_token, token_expires_at)
       VALUES ('expireduser', 'expired@example.com', $1, FALSE, $2, NOW() - INTERVAL '1 hour')`,
      [passwordHash, expiredToken]
    );
    const res = await request(app).get(`/api/auth/verify-email?token=${expiredToken}`);
    expect(res.status).toBe(400);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/resend-verification
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/resend-verification', () => {
  it('200 — returns generic message regardless of user existence', async () => {
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ identifier: 'nobody@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.message).toBeTruthy();
  });

  it('200 — updates verify token for unverified user', async () => {
    const user = await insertUnverifiedUser();
    const oldToken = user.verify_token;

    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ identifier: user.email });
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT verify_token FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].verify_token).not.toBe(oldToken);
  });

  it('200 — same generic message when user is already verified', async () => {
    const user = await insertVerifiedUser();
    const res = await request(app)
      .post('/api/auth/resend-verification')
      .send({ identifier: user.email });
    expect(res.status).toBe(200);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/login
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/login', () => {
  it('200 — login with email returns accessToken, refreshToken and user', async () => {
    await insertVerifiedUser({ email: 'login@example.com', password: 'Password1' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'login@example.com', password: 'Password1' });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    expect(res.body.user.email).toBe('login@example.com');
  });

  it('200 — login with username', async () => {
    await insertVerifiedUser({ username: 'loginuser', password: 'Password1' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'loginuser', password: 'Password1' });
    expect(res.status).toBe(200);
  });

  it('200 — login updates last_login_at', async () => {
    const user = await insertVerifiedUser({ email: 'lastlogin@example.com', password: 'Password1' });
    await request(app).post('/api/auth/login').send({ identifier: 'lastlogin@example.com', password: 'Password1' });
    const dbUser = await pool.query('SELECT last_login_at FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].last_login_at).not.toBeNull();
  });

  it('401 — wrong password returns generic error', async () => {
    await insertVerifiedUser({ email: 'wrongpw@example.com', password: 'Password1' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'wrongpw@example.com', password: 'WrongPass1' });
    expect(res.status).toBe(401);
  });

  it('401 — non-existent user returns generic error', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'ghost@example.com', password: 'Password1' });
    expect(res.status).toBe(401);
  });

  it('412 — unverified email', async () => {
    await insertUnverifiedUser({ email: 'unverif@example.com', password: 'Password1' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'unverif@example.com', password: 'Password1' });
    expect(res.status).toBe(412);
  });

  it('401 — suspended account', async () => {
    await insertVerifiedUser({ email: 'suspended@example.com', password: 'Password1', isSuspended: true });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'suspended@example.com', password: 'Password1' });
    expect(res.status).toBe(401);
  });

  it('401 — soft-deleted account', async () => {
    await insertVerifiedUser({ email: 'deleted@example.com', password: 'Password1', deletedAt: new Date() });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'deleted@example.com', password: 'Password1' });
    expect(res.status).toBe(401);
  });

  it('increments failed_login_attempts on wrong password', async () => {
    const user = await insertVerifiedUser({ email: 'attempts@example.com', password: 'Password1' });
    await request(app).post('/api/auth/login').send({ identifier: 'attempts@example.com', password: 'Wrong1' });
    const dbUser = await pool.query('SELECT failed_login_attempts FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].failed_login_attempts).toBe(1);
  });

  it('423 — locks account after 5 failed attempts', async () => {
    await insertVerifiedUser({ email: 'lockout@example.com', password: 'Password1' });
    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send({ identifier: 'lockout@example.com', password: 'Wrong1' });
    }
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'lockout@example.com', password: 'Password1' });
    expect(res.status).toBe(423);
  });

  it('resets failed_login_attempts after successful login', async () => {
    const user = await insertVerifiedUser({ email: 'resetattempts@example.com', password: 'Password1' });
    await request(app).post('/api/auth/login').send({ identifier: 'resetattempts@example.com', password: 'Wrong1' });
    await request(app).post('/api/auth/login').send({ identifier: 'resetattempts@example.com', password: 'Password1' });
    const dbUser = await pool.query('SELECT failed_login_attempts FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].failed_login_attempts).toBe(0);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/refresh
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/refresh', () => {
  it('200 — returns new accessToken and rotated refreshToken', async () => {
    const user = await insertVerifiedUser({ email: 'refresh@example.com', password: 'Password1' });
    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'refresh@example.com', password: 'Password1' });
    const { refreshToken } = loginRes.body;

    const res = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    expect(res.body.refreshToken).not.toBe(refreshToken);
  });

  it('401 — old refresh token is invalidated after rotation', async () => {
    await insertVerifiedUser({ email: 'rotate@example.com', password: 'Password1' });
    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'rotate@example.com', password: 'Password1' });
    const { refreshToken } = loginRes.body;

    await request(app).post('/api/auth/refresh').send({ refreshToken });
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(res.status).toBe(401);
  });

  it('401 — invalid refresh token', async () => {
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken: uuidv4() });
    expect(res.status).toBe(401);
  });

  it('401 — missing refresh token', async () => {
    const res = await request(app).post('/api/auth/refresh').send({});
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/logout
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/logout', () => {
  it('200 — logout succeeds and increments token_version', async () => {
    const user = await insertVerifiedUser({ email: 'logout@example.com', password: 'Password1' });
    const token = makeToken(user);

    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT token_version FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].token_version).toBe(2);
  });

  it('200 — logout with refresh token deletes it from DB', async () => {
    await insertVerifiedUser({ email: 'logoutrt@example.com', password: 'Password1' });
    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'logoutrt@example.com', password: 'Password1' });
    const { refreshToken, user: loginUser } = loginRes.body;
    const dbUserRow = await pool.query('SELECT id, token_version FROM users WHERE id = $1', [loginUser.id]);
    const token = makeToken({ id: loginUser.id, username: loginUser.username, email: loginUser.email, token_version: dbUserRow.rows[0].token_version });

    await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .send({ refreshToken });

    const rts = await pool.query('SELECT * FROM user_refresh_tokens WHERE user_id = $1', [loginUser.id]);
    expect(rts.rows).toHaveLength(0);
  });

  it('401 — logout without token', async () => {
    const res = await request(app).post('/api/auth/logout').send({});
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/users/preferences
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/users/preferences', () => {
  it('200 — returns default preferences', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .get('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.search_radius_km).toBe(25);
    expect(res.body.location_update_frequency).toBe(5);
  });

  it('401 — no token', async () => {
    const res = await request(app).get('/api/users/preferences');
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/users/preferences
// ════════════════════════════════════════════════════════════════════════════

describe('PATCH /api/users/preferences', () => {
  it('200 — updates search_radius_km', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({ search_radius_km: 10 });
    expect(res.status).toBe(200);
    expect(res.body.preferences.search_radius_km).toBe(10);

    const dbPref = await pool.query('SELECT search_radius_km FROM preferences WHERE user_id = $1', [user.id]);
    expect(dbPref.rows[0].search_radius_km).toBe(10);
  });

  it('200 — updates location_update_frequency to 15', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({ location_update_frequency: 15 });
    expect(res.status).toBe(200);
    expect(res.body.preferences.location_update_frequency).toBe(15);
  });

  it('400 — radius below minimum (1 km)', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({ search_radius_km: 0 });
    expect(res.status).toBe(400);
  });

  it('400 — radius above maximum (50 km)', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({ search_radius_km: 51 });
    expect(res.status).toBe(400);
  });

  it('400 — invalid frequency (not 5, 15, or 30)', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({ location_update_frequency: 10 });
    expect(res.status).toBe(400);
  });

  it('400 — no fields sent', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/preferences')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/users/profile
// ════════════════════════════════════════════════════════════════════════════

describe('PATCH /api/users/profile', () => {
  it('200 — updates username', async () => {
    const user = await insertVerifiedUser({ username: 'oldname' });
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'newname12' });
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('newname12');

    const dbUser = await pool.query('SELECT username FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].username).toBe('newname12');
  });

  it('200 — updates biography', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ biography: 'Hello world' });
    expect(res.status).toBe(200);
    expect(res.body.biography).toBe('Hello world');
  });

  it('200 — strips HTML tags from biography', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ biography: '<script>alert("xss")</script>Hello' });
    expect(res.status).toBe(200);
    expect(res.body.biography).toBe('Hello');
  });

  it('409 — username already taken by another user', async () => {
    const user1 = await insertVerifiedUser({ username: 'taken1234' });
    const user2 = await insertVerifiedUser({ username: 'myname12', email: 'user2@example.com' });
    const token = makeToken(user2);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'taken1234' });
    expect(res.status).toBe(409);
    // Unused variable suppression
    void user1;
  });

  it('200 — can update username to same value (own username)', async () => {
    const user = await insertVerifiedUser({ username: 'sameuser' });
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'sameuser' });
    expect(res.status).toBe(200);
  });

  it('400 — no fields sent', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('400 — username too short', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'ab' });
    expect(res.status).toBe(400);
  });

  it('400 — biography exceeds 150 characters', async () => {
    const user = await insertVerifiedUser();
    const token = makeToken(user);
    const res = await request(app)
      .patch('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ biography: 'x'.repeat(151) });
    expect(res.status).toBe(400);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/users/delete (soft-delete)
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/users/delete', () => {
  it('200 — soft-deletes account (sets deleted_at)', async () => {
    const user = await insertVerifiedUser({ email: 'todelete@example.com', password: 'Password1' });
    const token = makeToken(user);
    const res = await request(app)
      .post('/api/users/delete')
      .set('Authorization', `Bearer ${token}`)
      .send({ password: 'Password1' });
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT deleted_at FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].deleted_at).not.toBeNull();
  });

  it('401 — wrong password', async () => {
    const user = await insertVerifiedUser({ email: 'deletewrong@example.com', password: 'Password1' });
    const token = makeToken(user);
    const res = await request(app)
      .post('/api/users/delete')
      .set('Authorization', `Bearer ${token}`)
      .send({ password: 'WrongPass1' });
    expect(res.status).toBe(401);
  });

  it('401 — no token', async () => {
    const res = await request(app).post('/api/users/delete').send({ password: 'Password1' });
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/forgot-password
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/forgot-password', () => {
  it('200 — returns generic message regardless of whether user exists', async () => {
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ identifier: 'nobody@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.message).toBeTruthy();
  });

  it('200 — sets password_reset_token for existing user', async () => {
    const user = await insertVerifiedUser({ email: 'forgot@example.com' });
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ identifier: 'forgot@example.com' });
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT password_reset_token FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].password_reset_token).not.toBeNull();
  });

  it('200 — throttles repeated requests (returns generic message again)', async () => {
    await insertVerifiedUser({ email: 'throttle@example.com' });
    await request(app).post('/api/auth/forgot-password').send({ identifier: 'throttle@example.com' });
    const res = await request(app).post('/api/auth/forgot-password').send({ identifier: 'throttle@example.com' });
    expect(res.status).toBe(200);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/reset-password
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/reset-password', () => {
  async function setupResetToken(email = 'reset@example.com') {
    const user = await insertVerifiedUser({ email });
    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3',
      [token, expiresAt, user.id]
    );
    return { user, token };
  }

  it('200 — resets password and invalidates token', async () => {
    const { user, token } = await setupResetToken();
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(200);

    const dbUser = await pool.query('SELECT password_reset_token FROM users WHERE id = $1', [user.id]);
    expect(dbUser.rows[0].password_reset_token).toBeNull();
  });

  it('400 — passwords do not match', async () => {
    const { token } = await setupResetToken('mismatch@example.com');
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewPass1word', confirmPassword: 'Different1' });
    expect(res.status).toBe(400);
  });

  it('400 — same password as current', async () => {
    const { token } = await setupResetToken('samepass@example.com');
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'Password1', confirmPassword: 'Password1' });
    expect(res.status).toBe(400);
  });

  it('400 — invalid token', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: uuidv4(), password: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(400);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/change-password
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/auth/change-password', () => {
  it('200 — changes password successfully and deletes all refresh tokens', async () => {
    const user = await insertVerifiedUser({ email: 'changepw@example.com', password: 'Password1' });
    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'changepw@example.com', password: 'Password1' });
    const dbUserRow = await pool.query('SELECT token_version FROM users WHERE id = $1', [user.id]);
    const token = makeToken({ ...user, token_version: dbUserRow.rows[0].token_version });

    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'Password1', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(200);

    const rts = await pool.query('SELECT * FROM user_refresh_tokens WHERE user_id = $1', [user.id]);
    expect(rts.rows).toHaveLength(0);
    void loginRes;
  });

  it('401 — wrong current password', async () => {
    const user = await insertVerifiedUser({ email: 'changepwwrong@example.com', password: 'Password1' });
    const token = makeToken(user);
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'WrongPass1', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(401);
  });

  it('400 — new password same as current', async () => {
    const user = await insertVerifiedUser({ email: 'samenewpw@example.com', password: 'Password1' });
    const token = makeToken(user);
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'Password1', newPassword: 'Password1', confirmPassword: 'Password1' });
    expect(res.status).toBe(400);
  });

  it('400 — passwords do not match', async () => {
    const user = await insertVerifiedUser({ email: 'mismatchpw@example.com', password: 'Password1' });
    const token = makeToken(user);
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'Password1', newPassword: 'NewPass1word', confirmPassword: 'Different2' });
    expect(res.status).toBe(400);
  });

  it('423 — locks account after 3 failed change-password attempts', async () => {
    const user = await insertVerifiedUser({ email: 'lockpw@example.com', password: 'Password1' });
    const token = makeToken(user);
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: 'Wrong1pass', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });
    }
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'Password1', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(423);
  });

  it('401 — no token', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .send({ currentPassword: 'Password1', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/users/search
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/users/search', () => {
  it('200 — returns matching users', async () => {
    const searcher = await insertVerifiedUser({ username: 'searcher1', email: 'searcher@example.com' });
    await insertVerifiedUser({ username: 'findable1', email: 'findable@example.com' });
    const token = makeToken(searcher);

    const res = await request(app)
      .get('/api/users/search?q=find')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.users.some(u => u.username === 'findable1')).toBe(true);
  });

  it('200 — excludes deleted users', async () => {
    const searcher = await insertVerifiedUser({ username: 'searcher2', email: 'searcher2@example.com' });
    await insertVerifiedUser({ username: 'deleted99', email: 'del99@example.com', deletedAt: new Date() });
    const token = makeToken(searcher);

    const res = await request(app)
      .get('/api/users/search?q=deleted99')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.users.every(u => u.username !== 'deleted99')).toBe(true);
  });

  it('401 — no token', async () => {
    const res = await request(app).get('/api/users/search?q=user');
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Multi-step flow: register → verify → login → logout → refresh rejected
// ════════════════════════════════════════════════════════════════════════════

describe('Full auth flow: register → verify → login → logout → refresh rejected', () => {
  it('completes full lifecycle', async () => {
    // 1. Register
    const registerRes = await request(app).post('/api/users/register').send({
      username: 'flowuser',
      email: 'flow@example.com',
      password: 'FlowPass1',
      acceptedTerms: true,
    });
    expect(registerRes.status).toBe(201);

    // 2. Grab verify token from DB
    const dbUser = await pool.query('SELECT verify_token FROM users WHERE email = $1', ['flow@example.com']);
    const verifyToken = dbUser.rows[0].verify_token;

    // 3. Verify email
    const verifyRes = await request(app).get(`/api/auth/verify-email?token=${verifyToken}`);
    expect(verifyRes.status).toBe(200);

    // 4. Login
    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'flow@example.com', password: 'FlowPass1' });
    expect(loginRes.status).toBe(200);
    const { accessToken, refreshToken } = loginRes.body;

    // 5. Access protected endpoint
    const prefRes = await request(app).get('/api/users/preferences').set('Authorization', `Bearer ${accessToken}`);
    expect(prefRes.status).toBe(200);

    // 6. Logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ refreshToken });
    expect(logoutRes.status).toBe(200);

    // 7. Refresh token rejected after logout
    const refreshRes = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(refreshRes.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Multi-step flow: login → change password → old refresh token rejected
// ════════════════════════════════════════════════════════════════════════════

describe('Change password invalidates existing sessions', () => {
  it('all refresh tokens removed after password change', async () => {
    await insertVerifiedUser({ email: 'session@example.com', password: 'Password1' });

    const loginRes = await request(app).post('/api/auth/login').send({ identifier: 'session@example.com', password: 'Password1' });
    const { refreshToken, user: loginUser } = loginRes.body;
    const dbUserRow = await pool.query('SELECT token_version FROM users WHERE id = $1', [loginUser.id]);
    const accessToken = makeToken({ id: loginUser.id, username: loginUser.username, email: loginUser.email, token_version: dbUserRow.rows[0].token_version });

    await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ currentPassword: 'Password1', newPassword: 'NewPass1word', confirmPassword: 'NewPass1word' });

    const refreshRes = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(refreshRes.status).toBe(401);
  });
});
