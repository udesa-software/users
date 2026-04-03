const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { adminAuthService } = require('../admin-auth.service');
const { adminRepository } = require('../../admins/admin.repository');
const { sendPasswordChangedEmail } = require('../../../config/mailer');

jest.mock('../../admins/admin.repository', () => ({
  adminRepository: {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    incrementFailedAttempts: jest.fn(),
    resetFailedAttempts: jest.fn(),
    incrementTokenVersion: jest.fn(),
    updatePassword: jest.fn(),
  },
}));

jest.mock('../../../config/mailer', () => ({
  sendPasswordChangedEmail: jest.fn(),
}));

jest.mock('../../../config/env', () => ({
  env: { JWT_SECRET: 'test-secret', JWT_EXPIRES_IN: '8h' },
}));

jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

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
    jwt.sign.mockReturnValue('jwt-token-mock');
    adminRepository.resetFailedAttempts.mockResolvedValue();
    adminRepository.incrementFailedAttempts.mockResolvedValue();
  });

  it('devuelve token y datos del admin cuando las credenciales son correctas', async () => {
    const result = await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(result.token).toBe('jwt-token-mock');
    expect(result.admin).toMatchObject({ id: 'admin-uuid-1', role: 'superadmin' });
  });

  it('normaliza el email a minúsculas antes de buscar', async () => {
    await adminAuthService.login({ email: 'ADMIN@UDESA.EDU.AR', password: 'Password1' });

    expect(adminRepository.findByEmail).toHaveBeenCalledWith('admin@udesa.edu.ar');
  });

  it('genera el JWT con el rol y must_change_password incluidos', async () => {
    await adminAuthService.login({ email: 'admin@udesa.edu.ar', password: 'Password1' });

    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ role: 'superadmin', must_change_password: false }),
      'test-secret',
      { expiresIn: '8h' }
    );
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
  beforeEach(() => jest.clearAllMocks());

  it('incrementa el token_version para revocar todas las sesiones', async () => {
    adminRepository.incrementTokenVersion.mockResolvedValue();

    await adminAuthService.logout('admin-uuid-1');

    expect(adminRepository.incrementTokenVersion).toHaveBeenCalledWith('admin-uuid-1');
  });

  it('devuelve un mensaje de confirmación', async () => {
    adminRepository.incrementTokenVersion.mockResolvedValue();

    const result = await adminAuthService.logout('admin-uuid-1');

    expect(result.message).toBeDefined();
  });
});

// changePassword
describe('adminAuthService.changePassword', () => {
  const INPUT_VALIDO = { currentPassword: 'TempPass1', newPassword: 'NuevaPassword1' };

  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.findById.mockResolvedValue(ADMIN_DB);
    bcrypt.compare
      .mockResolvedValueOnce(true)  // contraseña actual correcta
      .mockResolvedValueOnce(false); // nueva contraseña ≠ anterior
    bcrypt.hash.mockResolvedValue('nuevo-hash');
    adminRepository.updatePassword.mockResolvedValue();
    sendPasswordChangedEmail.mockResolvedValue();
  });

  it('actualiza la contraseña y limpia must_change_password', async () => {
    await adminAuthService.changePassword('admin-uuid-1', INPUT_VALIDO);

    expect(bcrypt.hash).toHaveBeenCalledWith('NuevaPassword1', 12);
    expect(adminRepository.updatePassword).toHaveBeenCalledWith('admin-uuid-1', 'nuevo-hash');
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
