const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { authService } = require('../../src/modules/auth/auth.service');
const { userRepository } = require('../../src/modules/users/user.repository');
const { sendResetPasswordEmail, sendPasswordChangedEmail } = require('../../src/config/mailer');

jest.mock('../../src/modules/users/user.repository', () => ({
  userRepository: {
    findByEmail: jest.fn(),
    findByUsername: jest.fn(),
    findById: jest.fn(),
    findByPasswordResetToken: jest.fn(),
    incrementFailedAttempts: jest.fn(),
    resetFailedAttempts: jest.fn(),
    incrementTokenVersion: jest.fn(),
    updatePasswordResetToken: jest.fn(),
    updateLastResetRequest: jest.fn(),
    updatePasswordAndInvalidateResetToken: jest.fn(),
    createRefreshToken: jest.fn(),
    rotateRefreshToken: jest.fn(),
    deleteRefreshToken: jest.fn(),
    deleteAllRefreshTokensForUser: jest.fn(),
  },
}));

jest.mock('../../src/config/mailer', () => ({
  sendResetPasswordEmail: jest.fn(),
  sendPasswordChangedEmail: jest.fn(),
}));

jest.mock('../../src/config/env', () => ({
  env: { JWT_SECRET: 'test-secret', ACCESS_TOKEN_EXPIRES_IN: '15m', REFRESH_TOKEN_EXPIRES_IN: '7d' },
}));

jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('uuid');

const USUARIO_DB = {
  id: 'user-uuid-1',
  username: 'testuser',
  email: 'test@example.com',
  password_hash: 'hashed_password',
  is_verified: true,
  deleted_at: null,
  is_suspended: false,
  locked_until: null,
  token_version: 1,
  last_reset_request_at: null,
  created_at: new Date('2024-01-01'),
};

const BLOQUEADO_HASTA = new Date(Date.now() + 15 * 60 * 1000);

// login

describe('authService.login', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);
    userRepository.findByUsername.mockResolvedValue(USUARIO_DB);
    bcrypt.compare.mockResolvedValue(true);
    jwt.sign.mockReturnValue('access-token-mock');
    uuidv4.mockReturnValue('refresh-uuid-mock');
    userRepository.resetFailedAttempts.mockResolvedValue();
    userRepository.incrementFailedAttempts.mockResolvedValue();
    userRepository.createRefreshToken.mockResolvedValue();
  });

  it('devuelve accessToken, refreshToken y datos del usuario cuando las credenciales son correctas', async () => {
    const result = await authService.login({ identifier: 'test@example.com', password: 'Password1' });

    expect(result.accessToken).toBe('access-token-mock');
    expect(result.refreshToken).toBe('refresh-uuid-mock');
    expect(result.user).toMatchObject({ id: 'user-uuid-1', username: 'testuser' });
  });

  it('guarda el refresh token opaco en la BD', async () => {
    await authService.login({ identifier: 'test@example.com', password: 'Password1' });

    expect(userRepository.createRefreshToken).toHaveBeenCalledWith(
      'user-uuid-1',
      'refresh-uuid-mock',
      expect.any(Date)
    );
  });

  it('genera el access token JWT con los datos del usuario', async () => {
    await authService.login({ identifier: 'test@example.com', password: 'Password1' });

    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-uuid-1', username: 'testuser', token_version: 1, type: 'access' }),
      'test-secret',
      { expiresIn: '15m' }
    );
    expect(jwt.sign).toHaveBeenCalledTimes(1);
  });

  it('busca por email cuando el identifier contiene @', async () => {
    await authService.login({ identifier: 'TEST@EXAMPLE.COM', password: 'Password1' });

    expect(userRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
    expect(userRepository.findByUsername).not.toHaveBeenCalled();
  });

  it('busca por username cuando el identifier no contiene @', async () => {
    await authService.login({ identifier: 'testuser', password: 'Password1' });

    expect(userRepository.findByUsername).toHaveBeenCalledWith('testuser');
    expect(userRepository.findByEmail).not.toHaveBeenCalled();
  });

  it('resetea el contador de intentos fallidos al loguear correctamente', async () => {
    await authService.login({ identifier: 'test@example.com', password: 'Password1' });

    expect(userRepository.resetFailedAttempts).toHaveBeenCalledWith('user-uuid-1');
  });

  it('lanza error 401 genérico si el usuario no existe', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    await expect(
      authService.login({ identifier: 'noexiste@x.com', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 401, message: 'Credenciales inválidas' });
  });

  it('lanza error 403 si la cuenta fue eliminada (soft-delete)', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, deleted_at: new Date() });

    await expect(
      authService.login({ identifier: 'test@example.com', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('lanza error 403 si la cuenta está suspendida por un admin', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_suspended: true });

    await expect(
      authService.login({ identifier: 'test@example.com', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('lanza error 423 si la cuenta está bloqueada por intentos fallidos', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, locked_until: BLOQUEADO_HASTA });

    await expect(
      authService.login({ identifier: 'test@example.com', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 423 });
  });

  it('lanza error 403 si el email no está verificado', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: false });

    await expect(
      authService.login({ identifier: 'test@example.com', password: 'Password1' })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('lanza error 401 genérico si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(
      authService.login({ identifier: 'test@example.com', password: 'wrong' })
    ).rejects.toMatchObject({ statusCode: 401, message: 'Credenciales inválidas' });
  });

  it('incrementa el contador de intentos fallidos si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(authService.login({ identifier: 'test@example.com', password: 'wrong' })).rejects.toThrow();
    expect(userRepository.incrementFailedAttempts).toHaveBeenCalledWith('user-uuid-1', 5);
  });
});

// logout

describe('authService.logout', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.deleteRefreshToken.mockResolvedValue();
    userRepository.incrementTokenVersion.mockResolvedValue();
  });

  it('incrementa el token_version para invalidar el access token inmediatamente', async () => {
    await authService.logout('user-uuid-1', 'some-refresh-token');

    expect(userRepository.incrementTokenVersion).toHaveBeenCalledWith('user-uuid-1');
  });

  it('borra el refresh token específico de la BD', async () => {
    await authService.logout('user-uuid-1', 'some-refresh-token');

    expect(userRepository.deleteRefreshToken).toHaveBeenCalledWith('some-refresh-token');
  });

  it('funciona sin refresh token (no falla si la cookie no estaba)', async () => {
    await authService.logout('user-uuid-1');

    expect(userRepository.deleteRefreshToken).not.toHaveBeenCalled();
    expect(userRepository.incrementTokenVersion).toHaveBeenCalledWith('user-uuid-1');
  });

  it('devuelve un mensaje de confirmación', async () => {
    const result = await authService.logout('user-uuid-1', 'some-refresh-token');

    expect(result.message).toBeDefined();
  });
});

// requestPasswordReset

describe('authService.requestPasswordReset', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    uuidv4.mockReturnValue('reset-token-uuid');
    userRepository.updatePasswordResetToken.mockResolvedValue();
    userRepository.updateLastResetRequest.mockResolvedValue();
    sendResetPasswordEmail.mockResolvedValue();
  });

  it('devuelve mensaje genérico si el email no está registrado', async () => {
    userRepository.findByEmail.mockResolvedValue(null);
    userRepository.findByUsername.mockResolvedValue(null);

    const result = await authService.requestPasswordReset('noexiste@x.com');

    expect(result.message).toBeDefined();
    expect(userRepository.updatePasswordResetToken).not.toHaveBeenCalled();
  });

  it('busca por username si el identifier no tiene @', async () => {
    userRepository.findByEmail.mockResolvedValue(null);
    userRepository.findByUsername.mockResolvedValue(USUARIO_DB);

    await authService.requestPasswordReset('testuser');

    expect(userRepository.findByUsername).toHaveBeenCalledWith('testuser');
  });

  it('devuelve mensaje genérico si el usuario está en throttle (menos de 1 min)', async () => {
    const hacePocoTiempo = new Date(Date.now() - 30 * 1000);
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, last_reset_request_at: hacePocoTiempo });

    const result = await authService.requestPasswordReset('test@example.com');

    expect(result.message).toBeDefined();
    expect(userRepository.updatePasswordResetToken).not.toHaveBeenCalled();
  });

  it('genera un token y lo guarda si pasó más de 1 minuto desde el último pedido', async () => {
    const haceUnMinuto = new Date(Date.now() - 61 * 1000);
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, last_reset_request_at: haceUnMinuto });

    await authService.requestPasswordReset('test@example.com');

    expect(userRepository.updatePasswordResetToken).toHaveBeenCalledWith(
      'user-uuid-1',
      'reset-token-uuid',
      expect.any(Date)
    );
  });

  it('actualiza el timestamp del último pedido', async () => {
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);

    await authService.requestPasswordReset('test@example.com');

    expect(userRepository.updateLastResetRequest).toHaveBeenCalledWith('user-uuid-1');
  });

  it('envía el email con el token de reset', async () => {
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);

    await authService.requestPasswordReset('test@example.com');
    await Promise.resolve();

    expect(sendResetPasswordEmail).toHaveBeenCalledWith('test@example.com', 'reset-token-uuid');
  });

  it('no falla si el envío del email falla', async () => {
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);
    sendResetPasswordEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(authService.requestPasswordReset('test@example.com')).resolves.toBeDefined();
  });

  it('devuelve siempre el mismo mensaje genérico (no revela si existe el usuario)', async () => {
    userRepository.findByEmail.mockResolvedValue(null);
    userRepository.findByUsername.mockResolvedValue(null);
    const resultSinUsuario = await authService.requestPasswordReset('noexiste@x.com');

    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);
    const resultConUsuario = await authService.requestPasswordReset('test@example.com');

    expect(resultSinUsuario.message).toBe(resultConUsuario.message);
  });
});

// verifyResetToken

describe('authService.verifyResetToken', () => {
  beforeEach(() => jest.clearAllMocks());

  it('devuelve mensaje y token si el token es válido', async () => {
    userRepository.findByPasswordResetToken.mockResolvedValue(USUARIO_DB);

    const result = await authService.verifyResetToken('token-valido');

    expect(result.token).toBe('token-valido');
    expect(result.message).toBeDefined();
  });

  it('lanza error 400 si el token es undefined o vacío', async () => {
    await expect(authService.verifyResetToken(undefined)).rejects.toMatchObject({ statusCode: 400 });
    await expect(authService.verifyResetToken('')).rejects.toMatchObject({ statusCode: 400 });
  });

  it('lanza error 400 si el token no existe o expiró', async () => {
    userRepository.findByPasswordResetToken.mockResolvedValue(null);

    await expect(authService.verifyResetToken('token-vencido')).rejects.toMatchObject({ statusCode: 400 });
  });
});

// resetPassword

describe('authService.resetPassword', () => {
  const INPUT_VALIDO = {
    token: 'reset-token',
    password: 'NuevaPassword1',
    confirmPassword: 'NuevaPassword1',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findByPasswordResetToken.mockResolvedValue(USUARIO_DB);
    bcrypt.compare.mockResolvedValue(false);
    bcrypt.hash.mockResolvedValue('nuevo-hash');
    userRepository.updatePasswordAndInvalidateResetToken.mockResolvedValue();
    userRepository.deleteAllRefreshTokensForUser.mockResolvedValue();
  });

  it('actualiza la contraseña e invalida el token cuando todo es válido', async () => {
    await authService.resetPassword(INPUT_VALIDO);

    expect(bcrypt.hash).toHaveBeenCalledWith('NuevaPassword1', 12);
    expect(userRepository.updatePasswordAndInvalidateResetToken).toHaveBeenCalledWith('user-uuid-1', 'nuevo-hash');
  });

  it('revoca todas las sesiones activas al resetear la contraseña (H5 CA.7)', async () => {
    await authService.resetPassword(INPUT_VALIDO);

    expect(userRepository.deleteAllRefreshTokensForUser).toHaveBeenCalledWith('user-uuid-1');
  });

  it('devuelve un mensaje de éxito', async () => {
    const result = await authService.resetPassword(INPUT_VALIDO);

    expect(result.message).toBeDefined();
  });

  it('lanza error 400 si las contraseñas no coinciden', async () => {
    await expect(
      authService.resetPassword({ ...INPUT_VALIDO, confirmPassword: 'OtraPassword1' })
    ).rejects.toMatchObject({ statusCode: 400 });

    expect(userRepository.updatePasswordAndInvalidateResetToken).not.toHaveBeenCalled();
  });

  it('lanza error 400 si el token es inválido o expiró', async () => {
    userRepository.findByPasswordResetToken.mockResolvedValue(null);

    await expect(authService.resetPassword(INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 400 });
  });

  it('lanza error 400 si la nueva contraseña es igual a la anterior', async () => {
    bcrypt.compare.mockResolvedValue(true);

    await expect(authService.resetPassword(INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 400 });
    expect(userRepository.updatePasswordAndInvalidateResetToken).not.toHaveBeenCalled();
  });
});

// refreshToken

describe('authService.refreshToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.rotateRefreshToken.mockResolvedValue('user-uuid-1');
    userRepository.findById.mockResolvedValue(USUARIO_DB);
    uuidv4.mockReturnValue('new-refresh-uuid');
    jwt.sign.mockReturnValue('new-access-token-mock');
  });

  it('devuelve nuevo accessToken y newRefreshToken cuando el token es válido', async () => {
    const result = await authService.refreshToken('valid-uuid-token');

    expect(result.accessToken).toBe('new-access-token-mock');
    expect(result.newRefreshToken).toBe('new-refresh-uuid');
  });

  it('genera el access token JWT con los datos del usuario', async () => {
    await authService.refreshToken('valid-uuid-token');

    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-uuid-1', type: 'access' }),
      'test-secret',
      { expiresIn: '15m' }
    );
  });

  it('delega la rotación atómica al repositorio con el token viejo y el nuevo', async () => {
    await authService.refreshToken('old-uuid-token');

    expect(userRepository.rotateRefreshToken).toHaveBeenCalledWith(
      'old-uuid-token',
      'new-refresh-uuid',
      expect.any(Date)
    );
  });

  it('lanza error 401 si el token no existe, expiró o ya fue usado (race condition)', async () => {
    userRepository.rotateRefreshToken.mockResolvedValue(null);

    await expect(authService.refreshToken('used-or-expired-token'))
      .rejects.toMatchObject({ statusCode: 401 });
  });

  it('lanza error 401 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(authService.refreshToken('valid-uuid-token'))
      .rejects.toMatchObject({ statusCode: 401 });
  });

  it('lanza error 403 si la cuenta fue eliminada (soft-delete)', async () => {
    userRepository.findById.mockResolvedValue({ ...USUARIO_DB, deleted_at: new Date() });

    await expect(authService.refreshToken('valid-uuid-token'))
      .rejects.toMatchObject({ statusCode: 403 });
  });

  it('lanza error 403 si la cuenta está suspendida', async () => {
    userRepository.findById.mockResolvedValue({ ...USUARIO_DB, is_suspended: true });

    await expect(authService.refreshToken('valid-uuid-token'))
      .rejects.toMatchObject({ statusCode: 403 });
  });
});

// changePassword

describe('authService.changePassword', () => {
  const INPUT_VALIDO = { currentPassword: 'Password1', newPassword: 'NuevaPassword1' };

  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findById.mockResolvedValue(USUARIO_DB);
    bcrypt.compare
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    bcrypt.hash.mockResolvedValue('nuevo-hash');
    userRepository.updatePasswordAndInvalidateResetToken.mockResolvedValue();
    userRepository.deleteAllRefreshTokensForUser.mockResolvedValue();
    userRepository.resetFailedAttempts.mockResolvedValue();
    sendPasswordChangedEmail.mockResolvedValue();
  });

  it('actualiza la contraseña e invalida todas las sesiones activas', async () => {
    await authService.changePassword('user-uuid-1', INPUT_VALIDO);

    expect(userRepository.updatePasswordAndInvalidateResetToken).toHaveBeenCalledWith('user-uuid-1', 'nuevo-hash');
  });

  it('elimina todos los refresh tokens del usuario al cambiar contraseña', async () => {
    await authService.changePassword('user-uuid-1', INPUT_VALIDO);

    expect(userRepository.deleteAllRefreshTokensForUser).toHaveBeenCalledWith('user-uuid-1');
  });

  it('resetea el contador de intentos fallidos al cambiar exitosamente', async () => {
    await authService.changePassword('user-uuid-1', INPUT_VALIDO);

    expect(userRepository.resetFailedAttempts).toHaveBeenCalledWith('user-uuid-1');
  });

  it('envía email de notificación al cambiar la contraseña', async () => {
    await authService.changePassword('user-uuid-1', INPUT_VALIDO);
    await Promise.resolve();

    expect(sendPasswordChangedEmail).toHaveBeenCalledWith('test@example.com');
  });

  it('no falla si el envío del email de notificación falla', async () => {
    sendPasswordChangedEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).resolves.toBeDefined();
  });

  it('devuelve un mensaje de éxito', async () => {
    const result = await authService.changePassword('user-uuid-1', INPUT_VALIDO);

    expect(result.message).toBeDefined();
  });

  it('lanza error 404 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 404 });
  });

  it('lanza error 423 si la cuenta está bloqueada', async () => {
    userRepository.findById.mockResolvedValue({ ...USUARIO_DB, locked_until: BLOQUEADO_HASTA });

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 423 });
  });

  it('resetea el contador de intentos cuando el bloqueo ya expiró (bug fix)', async () => {
    const bloqueadoHaceRato = new Date(Date.now() - 60 * 1000); // expiró hace 1 min
    userRepository.findById.mockResolvedValue({ ...USUARIO_DB, locked_until: bloqueadoHaceRato });
    userRepository.resetFailedAttempts.mockResolvedValue();

    await authService.changePassword('user-uuid-1', INPUT_VALIDO);

    expect(userRepository.resetFailedAttempts).toHaveBeenCalledWith('user-uuid-1');
  });

  it('lanza error 401 si la contraseña actual es incorrecta', async () => {
    bcrypt.compare.mockReset();
    bcrypt.compare.mockResolvedValue(false);

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('incrementa intentos fallidos si la contraseña actual es incorrecta', async () => {
    bcrypt.compare.mockReset();
    bcrypt.compare.mockResolvedValue(false);
    userRepository.incrementFailedAttempts.mockResolvedValue();

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).rejects.toThrow();
    expect(userRepository.incrementFailedAttempts).toHaveBeenCalledWith('user-uuid-1', 3);
  });

  it('lanza error 400 si la nueva contraseña es igual a la actual', async () => {
    bcrypt.compare.mockReset();
    bcrypt.compare
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true);

    await expect(authService.changePassword('user-uuid-1', INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 400 });
    expect(userRepository.updatePasswordAndInvalidateResetToken).not.toHaveBeenCalled();
  });
});
