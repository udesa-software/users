const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { adminAuthService } = require('../../src/modules/admin-auth/admin-auth.service');
const { adminRepository } = require('../../src/modules/admins/admin.repository');
const { sendPasswordChangedEmail } = require('../../src/config/mailer');

jest.mock('../../src/modules/admins/admin.repository', () => ({
  adminRepository: {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    incrementFailedAttempts: jest.fn(),
    resetFailedAttempts: jest.fn(),
    incrementTokenVersion: jest.fn(),
    updatePassword: jest.fn(),
    createRefreshToken: jest.fn(),
    rotateRefreshToken: jest.fn(),
    deleteRefreshToken: jest.fn(),
    deleteAllRefreshTokensForAdmin: jest.fn(),
  },
}));

jest.mock('../../src/config/mailer', () => ({
  sendPasswordChangedEmail: jest.fn(),
}));

jest.mock('../../src/config/env', () => ({
  env: { JWT_SECRET: 'test-secret', ADMIN_JWT_SECRET: 'test-admin-secret', ACCESS_TOKEN_EXPIRES_IN: '15m', REFRESH_TOKEN_EXPIRES_IN: '7d' },
}));

jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('uuid');

const ADMIN_DB = {
  id: 'admin-uuid-1',
  email: 'admin@udesa.edu.ar',
  password_hash: 'hashed_password',
  role: 'superadmin',
  must_change_password: false,
  temp_password_expires_at: null,
  locked_until: null,
  token_version: 1,
};

const BLOQUEADO_HASTA = new Date(Date.now() + 30 * 60 * 1000);

// login

describe('adminAuthService.login', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.findByEmail.mockResolvedValue(ADMIN_DB);
    bcrypt.compare.mockResolvedValue(true);
    jwt.sign.mockReturnValue('access-token-mock');
    uuidv4.mockReturnValue('refresh-uuid-mock');
    adminRepository.resetFailedAttempts.mockResolvedValue();
    adminRepository.incrementFailedAttempts.mockResolvedValue();
    adminRepository.createRefreshToken.mockResolvedValue();
  });

  it('devuelve accessToken, refreshToken y datos del admin cuando las credenciales son correctas', async () => {
    const result = await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(result.accessToken).toBe('access-token-mock');
    expect(result.refreshToken).toBe('refresh-uuid-mock');
    expect(result.admin).toMatchObject({ id: 'admin-uuid-1', role: 'superadmin' });
  });

  it('guarda el refresh token opaco en la BD', async () => {
    await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(adminRepository.createRefreshToken).toHaveBeenCalledWith(
      'admin-uuid-1',
      'refresh-uuid-mock',
      expect.any(Date)
    );
  });

  it('genera el access token JWT con el rol incluido', async () => {
    await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ role: 'superadmin', must_change_password: false, type: 'access' }),
      'test-admin-secret',
      { expiresIn: '15m' }
    );
    expect(jwt.sign).toHaveBeenCalledTimes(1);
  });

  it('normaliza el email a minúsculas antes de buscar', async () => {
    await adminAuthService.login({ email: 'ADMIN@UDESA.EDU.AR', password: 'Password1' });

    expect(adminRepository.findByEmail).toHaveBeenCalledWith('admin@udesa.edu.ar');
  });

  it('resetea el contador de intentos fallidos al loguear exitosamente', async () => {
    await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(adminRepository.resetFailedAttempts).toHaveBeenCalledWith('admin-uuid-1');
  });

  it('lanza error 401 genérico si el admin no existe', async () => {
    adminRepository.findByEmail.mockResolvedValue(null);

    await expect(
      adminAuthService.login({ email: 'noexiste@udesa.edu.ar', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 401, message: 'Credenciales inválidas' });
  });

  it('lanza error 423 si la cuenta está bloqueada por intentos fallidos', async () => {
    adminRepository.findByEmail.mockResolvedValue({ ...ADMIN_DB, locked_until: BLOQUEADO_HASTA });

    await expect(
      adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 423 });
  });

  it('lanza error 401 genérico si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(
      adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'wrong' })
    ).rejects.toMatchObject({ statusCode: 401, message: 'Credenciales inválidas' });
  });

  it('incrementa intentos fallidos con threshold 3 si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'wrong' })).rejects.toThrow();
    expect(adminRepository.incrementFailedAttempts).toHaveBeenCalledWith('admin-uuid-1', 3);
  });

  it('lanza error 403 si la contraseña temporal expiró', async () => {
    const expirada = new Date(Date.now() - 60 * 1000);
    adminRepository.findByEmail.mockResolvedValue({
      ...ADMIN_DB,
      must_change_password: true,
      temp_password_expires_at: expirada,
    });

    await expect(
      adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('permite login si must_change_password es true pero la contraseña NO expiró', async () => {
    const vigente = new Date(Date.now() + 60 * 60 * 1000);
    adminRepository.findByEmail.mockResolvedValue({
      ...ADMIN_DB,
      must_change_password: true,
      temp_password_expires_at: vigente,
    });

    const result = await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });
    expect(result.admin.must_change_password).toBe(true);
  });
});

// logout

describe('adminAuthService.logout', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.deleteRefreshToken.mockResolvedValue();
    adminRepository.incrementTokenVersion.mockResolvedValue();
  });

  it('incrementa el token_version para invalidar el access token inmediatamente', async () => {
    await adminAuthService.logout('admin-uuid-1', 'some-refresh-token');

    expect(adminRepository.incrementTokenVersion).toHaveBeenCalledWith('admin-uuid-1');
  });

  it('borra el refresh token específico de la BD', async () => {
    await adminAuthService.logout('admin-uuid-1', 'some-refresh-token');

    expect(adminRepository.deleteRefreshToken).toHaveBeenCalledWith('some-refresh-token');
  });

  it('funciona sin refresh token (no falla si la cookie no estaba)', async () => {
    await adminAuthService.logout('admin-uuid-1');

    expect(adminRepository.deleteRefreshToken).not.toHaveBeenCalled();
    expect(adminRepository.incrementTokenVersion).toHaveBeenCalledWith('admin-uuid-1');
  });

  it('devuelve un mensaje de confirmación', async () => {
    const result = await adminAuthService.logout('admin-uuid-1', 'some-refresh-token');

    expect(result.message).toBeDefined();
  });
});

// refreshToken

describe('adminAuthService.refreshToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.rotateRefreshToken.mockResolvedValue('admin-uuid-1');
    adminRepository.findById.mockResolvedValue(ADMIN_DB);
    uuidv4.mockReturnValue('new-refresh-uuid');
    jwt.sign.mockReturnValue('new-access-token-mock');
  });

  it('devuelve nuevo accessToken y newRefreshToken cuando el token es válido', async () => {
    const result = await adminAuthService.refreshToken('valid-uuid-token');

    expect(result.accessToken).toBe('new-access-token-mock');
    expect(result.newRefreshToken).toBe('new-refresh-uuid');
  });

  it('genera el access token JWT con el rol del admin', async () => {
    await adminAuthService.refreshToken('valid-uuid-token');

    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'admin-uuid-1', role: 'superadmin', type: 'access' }),
      'test-admin-secret',
      { expiresIn: '15m' }
    );
  });

  it('delega la rotación atómica al repositorio con el token viejo y el nuevo', async () => {
    await adminAuthService.refreshToken('old-uuid-token');

    expect(adminRepository.rotateRefreshToken).toHaveBeenCalledWith(
      'old-uuid-token',
      'new-refresh-uuid',
      expect.any(Date)
    );
  });

  it('lanza error 401 si el token no existe, expiró o ya fue usado (race condition)', async () => {
    adminRepository.rotateRefreshToken.mockResolvedValue(null);

    await expect(adminAuthService.refreshToken('used-or-expired-token'))
      .rejects.toMatchObject({ statusCode: 401 });
  });

  it('lanza error 401 si el admin no existe', async () => {
    adminRepository.findById.mockResolvedValue(null);

    await expect(adminAuthService.refreshToken('valid-uuid-token'))
      .rejects.toMatchObject({ statusCode: 401 });
  });
});

// changePassword

describe('adminAuthService.changePassword', () => {
  const INPUT_VALIDO = { currentPassword: 'TempPass1', newPassword: 'NuevaPassword1' };

  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.findById.mockResolvedValue(ADMIN_DB);
    bcrypt.compare
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    bcrypt.hash.mockResolvedValue('nuevo-hash');
    adminRepository.updatePassword.mockResolvedValue();
    adminRepository.deleteAllRefreshTokensForAdmin.mockResolvedValue();
    sendPasswordChangedEmail.mockResolvedValue();
  });

  it('actualiza la contraseña y limpia must_change_password', async () => {
    await adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO);

    expect(bcrypt.hash).toHaveBeenCalledWith('NuevaPassword1', 12);
    expect(adminRepository.updatePassword).toHaveBeenCalledWith('admin-uuid-1', 'nuevo-hash');
  });

  it('elimina todos los refresh tokens del admin al cambiar contraseña', async () => {
    await adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO);

    expect(adminRepository.deleteAllRefreshTokensForAdmin).toHaveBeenCalledWith('admin-uuid-1');
  });

  it('envía email de notificación al cambiar la contraseña', async () => {
    await adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO);
    await Promise.resolve();

    expect(sendPasswordChangedEmail).toHaveBeenCalledWith('admin@udesa.edu.ar');
  });

  it('no falla si el envío del email de notificación falla', async () => {
    sendPasswordChangedEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO)).resolves.toBeDefined();
  });

  it('devuelve un mensaje de éxito', async () => {
    const result = await adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO);

    expect(result.message).toBeDefined();
  });

  it('lanza error 404 si el admin no existe', async () => {
    adminRepository.findById.mockResolvedValue(null);

    await expect(adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO))
      .rejects.toMatchObject({ statusCode: 404 });
    expect(adminRepository.updatePassword).not.toHaveBeenCalled();
  });

  it('lanza error 401 si la contraseña actual es incorrecta', async () => {
    bcrypt.compare.mockReset();
    bcrypt.compare.mockResolvedValue(false);

    await expect(adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO))
      .rejects.toMatchObject({ statusCode: 401 });
    expect(adminRepository.updatePassword).not.toHaveBeenCalled();
  });

  it('lanza error 400 si la nueva contraseña es igual a la actual', async () => {
    bcrypt.compare.mockReset();
    bcrypt.compare
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true);

    await expect(adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO))
      .rejects.toMatchObject({ statusCode: 400 });
    expect(adminRepository.updatePassword).not.toHaveBeenCalled();
  });
});
