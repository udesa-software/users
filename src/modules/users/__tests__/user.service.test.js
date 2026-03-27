const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { userService } = require('../user.service');
const { userRepository } = require('../user.repository');
const { sendVerificationEmail } = require('../../../config/mailer');
const { AppError } = require('../../../middlewares/errorHandler');

// Reemplazamos los módulos reales por versiones falsas que controlamos.
// Usamos factory functions (el () => ...) para que Jest nunca llegue a
// leer los archivos reales (que dependen de la base de datos).

jest.mock('../user.repository', () => ({
  userRepository: {
    findByEmail: jest.fn(),
    findByUsername: jest.fn(),
    findByVerifyToken: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
    markVerified: jest.fn(),
    updateVerifyToken: jest.fn(),
    markDeleted: jest.fn(),
  },
}));

jest.mock('../../../config/mailer', () => ({
  sendVerificationEmail: jest.fn(),
}));

jest.mock('bcryptjs');
jest.mock('uuid');

// Datos de prueba 

const INPUT_VALIDO = {
  username: 'testuser',
  email: 'Test@Example.com',
  password: 'Password1',
  acceptedTerms: true,
};

const USUARIO_DB = {
  id: 'user-uuid-1',
  username: 'testuser',
  email: 'test@example.com',
  password_hash: 'hashed_password',
  is_verified: false,
};

// register

describe('userService.register', () => {
  // Antes de cada test limpiamos los mocks y configuramos defaults para que el email y username estén libres, el hash devuelva algo predecible, etc.
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findByEmail.mockResolvedValue(null);   // email libre
    userRepository.findByUsername.mockResolvedValue(null); // username libre
    bcrypt.hash.mockResolvedValue('hashed_password');
    uuidv4.mockReturnValue('mock-uuid');
    sendVerificationEmail.mockResolvedValue();
    userRepository.create.mockResolvedValue(USUARIO_DB);
  });

  it('devuelve el usuario creado cuando los datos son válidos', async () => {
    const result = await userService.register(INPUT_VALIDO);

    expect(result).toEqual(USUARIO_DB);
  });

  it('normaliza email y username a minúsculas antes de guardar', async () => {
    await userService.register({ ...INPUT_VALIDO, email: 'UPPER@TEST.COM', username: 'UPPER' });

    expect(userRepository.findByEmail).toHaveBeenCalledWith('upper@test.com');
    expect(userRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'upper@test.com', username: 'upper' })
    );
  });

  it('hashea la contraseña con bcrypt usando 12 rondas', async () => {
    await userService.register(INPUT_VALIDO);

    expect(bcrypt.hash).toHaveBeenCalledWith('Password1', 12);
    expect(userRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ passwordHash: 'hashed_password' })
    );
  });

  it('guarda el token y una fecha de expiración en el usuario', async () => {
    await userService.register(INPUT_VALIDO);

    expect(userRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({
        verifyToken: 'mock-uuid',
        tokenExpiresAt: expect.any(Date),
      })
    );
  });

  it('guarda que el usuario aceptó los términos y la fecha en que lo hizo', async () => {
    await userService.register(INPUT_VALIDO);

    expect(userRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ acceptedTerms: true, acceptedTermsAt: expect.any(Date) })
    );
  });

  it('envía el email de verificación al correo del usuario', async () => {
    await userService.register(INPUT_VALIDO);
    await Promise.resolve(); // espera
    expect(sendVerificationEmail).toHaveBeenCalledWith('test@example.com', 'mock-uuid');
  });

  it('no falla si el envío del email falla (el registro ya se guardó)', async () => {
    sendVerificationEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(userService.register(INPUT_VALIDO)).resolves.toBeDefined();
  });

  it('lanza error 409 si el email ya está registrado', async () => {
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);

    await expect(userService.register(INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 409 });
    expect(userRepository.create).not.toHaveBeenCalled();
  });

  it('lanza error 409 si el username ya está en uso', async () => {
    userRepository.findByUsername.mockResolvedValue(USUARIO_DB);

    await expect(userService.register(INPUT_VALIDO)).rejects.toMatchObject({ statusCode: 409 });
    expect(userRepository.create).not.toHaveBeenCalled();
  });

  it('lanza error 400 si acceptedTerms es false', async () => {
    await expect(
      userService.register({ ...INPUT_VALIDO, acceptedTerms: false })
    ).rejects.toMatchObject({ statusCode: 400 });

    expect(userRepository.create).not.toHaveBeenCalled();
  });

  it('lanza un AppError (no un Error genérico)', async () => {
    userRepository.findByEmail.mockResolvedValue(USUARIO_DB);

    await expect(userService.register(INPUT_VALIDO)).rejects.toBeInstanceOf(AppError);
  });
});

