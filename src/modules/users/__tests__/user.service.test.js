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
    findProfileById: jest.fn(),
    create: jest.fn(),
    markVerified: jest.fn(),
    updateVerifyToken: jest.fn(),
    markDeleted: jest.fn(),
    updateSearchRadius: jest.fn(),
    updateLocationFrequency: jest.fn(),
    getPreferences: jest.fn(),
    updateUsername: jest.fn(),
    updateBiography: jest.fn(),
  },
}));

jest.mock('../../../config/mailer', () => ({}));

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

  it('crea las preferencias por defecto al registrar el usuario (CA.5)', async () => {
    await userService.register(INPUT_VALIDO);

    expect(userRepository.create).toHaveBeenCalledTimes(1);
    // El repository.create es quien dispara el INSERT en preferences internamente;
    // desde el service solo verificamos que create fue llamado con los datos correctos
    // y que devolvió el usuario (el INSERT en preferences está encapsulado en el repo)
    expect(userRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'testuser', email: 'test@example.com' })
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


// delete
describe('userService.delete', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findById.mockResolvedValue(USUARIO_DB);
    bcrypt.compare.mockResolvedValue(true);
    userRepository.markDeleted.mockResolvedValue();
  });

  it('hace el soft-delete del usuario cuando la contraseña es correcta', async () => {
    await userService.delete('user-uuid-1', 'Password1');

    expect(userRepository.markDeleted).toHaveBeenCalledWith('user-uuid-1');
  });

  it('compara la contraseña ingresada contra el hash guardado en la base', async () => {
    await userService.delete('user-uuid-1', 'Password1');

    expect(bcrypt.compare).toHaveBeenCalledWith('Password1', 'hashed_password');
  });

  it('lanza error 404 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(userService.delete('user-uuid-1', 'Password1')).rejects.toMatchObject({ statusCode: 404 });
    expect(userRepository.markDeleted).not.toHaveBeenCalled();
  });

  it('lanza error 401 si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(userService.delete('user-uuid-1', 'wrong')).rejects.toMatchObject({ statusCode: 401 });
    expect(userRepository.markDeleted).not.toHaveBeenCalled();
  });
});

// getPreferences
describe('userService.getPreferences', () => {
  beforeEach(() => jest.clearAllMocks());

  it('devuelve las preferencias del usuario', async () => {
    const prefs = { search_radius_km: 25, location_update_frequency: 5 };
    userRepository.getPreferences.mockResolvedValue(prefs);

    const result = await userService.getPreferences('user-uuid-1');

    expect(userRepository.getPreferences).toHaveBeenCalledWith('user-uuid-1');
    expect(result).toEqual(prefs);
  });

  it('lanza error 404 si no se encuentran preferencias', async () => {
    userRepository.getPreferences.mockResolvedValue(null);

    await expect(userService.getPreferences('user-uuid-1')).rejects.toMatchObject({ statusCode: 404 });
  });
});

// updatePreferences
describe('userService.updatePreferences', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findById.mockResolvedValue(USUARIO_DB);
    userRepository.updateSearchRadius.mockResolvedValue({ search_radius_km: 10 });
    userRepository.updateLocationFrequency.mockResolvedValue({ location_update_frequency: 15 });
  });

  it('lanza error 404 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);
    await expect(userService.updatePreferences('user-uuid-1', { search_radius_km: 10 })).rejects.toMatchObject({ statusCode: 404 });
  });

  it('lanza error 400 si no se envian datos para actualizar', async () => {
    await expect(userService.updatePreferences('user-uuid-1', {})).rejects.toMatchObject({ statusCode: 400 });
    expect(userRepository.updateSearchRadius).not.toHaveBeenCalled();
    expect(userRepository.updateLocationFrequency).not.toHaveBeenCalled();
  });

  it('actualiza unicamente el radio de busqueda cuando se pasa ese parametro', async () => {
    const result = await userService.updatePreferences('user-uuid-1', { search_radius_km: 10 });
    expect(userRepository.updateSearchRadius).toHaveBeenCalledWith('user-uuid-1', 10);
    expect(userRepository.updateLocationFrequency).not.toHaveBeenCalled();
    expect(result).toEqual({ search_radius_km: 10 });
  });

  it('actualiza unicamente la frecuencia cuando se pasa ese parametro', async () => {
    const result = await userService.updatePreferences('user-uuid-1', { location_update_frequency: 15 });
    expect(userRepository.updateLocationFrequency).toHaveBeenCalledWith('user-uuid-1', 15);
    expect(userRepository.updateSearchRadius).not.toHaveBeenCalled();
    expect(result).toEqual({ location_update_frequency: 15 });
  });

  it('actualiza ambos previniendo sobreescritura indeseada si ambos son enviados', async () => {
    const result = await userService.updatePreferences('user-uuid-1', { search_radius_km: 10, location_update_frequency: 15 });
    expect(userRepository.updateSearchRadius).toHaveBeenCalledWith('user-uuid-1', 10);
    expect(userRepository.updateLocationFrequency).toHaveBeenCalledWith('user-uuid-1', 15);
    expect(result).toEqual({ search_radius_km: 10, location_update_frequency: 15 });
  });
});
describe('userService.updateProfile', () => {
  const USER_ID = 'user-uuid-1';
  const OTHER_USER_ID = 'user-uuid-2';

  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.findById.mockResolvedValue(USUARIO_DB);
    userRepository.findByUsername.mockResolvedValue(null); // username libre por defecto
    userRepository.updateUsername.mockResolvedValue({ id: USER_ID, username: 'nuevousername', email: 'test@example.com' });
    userRepository.updateBiography.mockResolvedValue({ biography: 'Mi nueva bio' });
  });

  // ─── usuario no existe ───
  it('lanza 404 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(userService.updateProfile(USER_ID, { username: 'nuevo' }))
      .rejects.toMatchObject({ statusCode: 404 });
  });

  it('lanza AppError si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(userService.updateProfile(USER_ID, { username: 'nuevo' }))
      .rejects.toBeInstanceOf(AppError);
  });

  // ─── CA.5: username vacío / solo espacios ───
  it('lanza 400 si el username es solo espacios en blanco (CA.5)', async () => {
    await expect(userService.updateProfile(USER_ID, { username: '   ' }))
      .rejects.toMatchObject({ statusCode: 400 });
    expect(userRepository.updateUsername).not.toHaveBeenCalled();
  });

  // ─── username duplicado ───
  it('lanza 409 si el username ya está en uso por otro usuario', async () => {
    userRepository.findByUsername.mockResolvedValue({ ...USUARIO_DB, id: OTHER_USER_ID });

    await expect(userService.updateProfile(USER_ID, { username: 'ocupado' }))
      .rejects.toMatchObject({ statusCode: 409 });
    expect(userRepository.updateUsername).not.toHaveBeenCalled();
  });

  it('no lanza si el username encontrado es del mismo usuario (no cambió el nombre)', async () => {
    userRepository.findByUsername.mockResolvedValue({ ...USUARIO_DB, id: USER_ID });
    userRepository.updateUsername.mockResolvedValue({ id: USER_ID, username: 'testuser', email: 'test@example.com' });

    const result = await userService.updateProfile(USER_ID, { username: 'testuser' });
    expect(result.username).toBe('testuser');
    expect(userRepository.updateUsername).toHaveBeenCalledWith(USER_ID, 'testuser');
  });

  // ─── éxito: solo username ───
  it('actualiza solo el username cuando solo se envía ese campo', async () => {
    const result = await userService.updateProfile(USER_ID, { username: 'nuevousername' });

    expect(result).toEqual({ username: 'nuevousername' });
    expect(userRepository.updateUsername).toHaveBeenCalledWith(USER_ID, 'nuevousername');
    expect(userRepository.updateBiography).not.toHaveBeenCalled();
  });

  // ─── éxito: solo biography ───
  it('actualiza solo la biography cuando solo se envía ese campo', async () => {
    const result = await userService.updateProfile(USER_ID, { biography: 'Mi nueva bio' });

    expect(result).toEqual({ biography: 'Mi nueva bio' });
    expect(userRepository.updateBiography).toHaveBeenCalled();
    expect(userRepository.updateUsername).not.toHaveBeenCalled();
  });

  // ─── éxito: ambos campos ───
  it('actualiza username y biography cuando se envían los dos', async () => {
    const result = await userService.updateProfile(USER_ID, {
      username: 'nuevousername',
      biography: 'Mi nueva bio',
    });

    expect(result).toEqual({ username: 'nuevousername', biography: 'Mi nueva bio' });
    expect(userRepository.updateUsername).toHaveBeenCalledWith(USER_ID, 'nuevousername');
    expect(userRepository.updateBiography).toHaveBeenCalled();
  });

  // ─── CA.4: sanitización de HTML ───
  it('elimina los tags HTML del biography antes de guardarlo — deja solo texto plano (CA.4)', async () => {
    userRepository.updateBiography.mockResolvedValue({ biography: 'alert(1)Hola mundo' });

    await userService.updateProfile(USER_ID, { biography: '<script>alert(1)</script>Hola mundo' });

    // El regex quita los tags (<script>...</script>) pero deja el contenido interno como texto plano.
    // "alert(1)" en texto llano no es ejecutable, el peligro de XSS viene de los tags.
    expect(userRepository.updateBiography).toHaveBeenCalledWith(USER_ID, 'alert(1)Hola mundo');
  });

  it('elimina tags HTML mezclados con texto normal (CA.4)', async () => {
    userRepository.updateBiography.mockResolvedValue({ biography: 'Soy  programador' });

    await userService.updateProfile(USER_ID, { biography: 'Soy <b>un</b> programador' });

    expect(userRepository.updateBiography).toHaveBeenCalledWith(USER_ID, 'Soy un programador');
  });

  // ─── CA.5: trim del username ───
  it('hace trim del username antes de validar y guardar (CA.5)', async () => {
    userRepository.updateUsername.mockResolvedValue({ id: USER_ID, username: 'trimmed', email: 'test@example.com' });

    await userService.updateProfile(USER_ID, { username: '  trimmed  ' });

    expect(userRepository.updateUsername).toHaveBeenCalledWith(USER_ID, 'trimmed');
  });

  // ─── CA.1: biography de exactamente 150 chars (límite exacto, pasa la validación Zod) ───
  it('guarda la biography cuando tiene exactamente 150 caracteres (CA.1)', async () => {
    const bio150 = 'a'.repeat(150);
    userRepository.updateBiography.mockResolvedValue({ biography: bio150 });

    const result = await userService.updateProfile(USER_ID, { biography: bio150 });

    expect(result.biography).toBe(bio150);
    expect(userRepository.updateBiography).toHaveBeenCalledWith(USER_ID, bio150);
  });

  // ─── biography que queda vacía tras sanitizar ───
  it('guarda biography vacía si el string era solo tags HTML', async () => {
    userRepository.updateBiography.mockResolvedValue({ biography: '' });

    await userService.updateProfile(USER_ID, { biography: '<b></b>' });

    expect(userRepository.updateBiography).toHaveBeenCalledWith(USER_ID, '');
  });
});
