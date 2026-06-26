const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { userService } = require('../../src/modules/users/user.service');
const { internalController } = require('../../src/modules/users/internal.controller');
const { userRepository } = require('../../src/modules/users/user.repository');
const { AppError: AppErrorInternal } = require('../../src/middlewares/errorHandler');
const { sendVerificationEmail } = require('../../src/config/mailer');
const { AppError } = require('../../src/middlewares/errorHandler');
const { friendsClient } = require('../../src/clients/friendsClient');
const { aiClient } = require('../../src/clients/aiClient');

// Reemplazamos los módulos reales por versiones falsas que controlamos.
// Usamos factory functions (el () => ...) para que Jest nunca llegue a
// leer los archivos reales (que dependen de la base de datos).

jest.mock('../../src/modules/users/user.repository', () => ({
  userRepository: {
    findByEmail: jest.fn(),
    findByUsername: jest.fn(),
    findByVerifyToken: jest.fn(),
    findById: jest.fn(),
    findProfileById: jest.fn(),
    findProfilesByIds: jest.fn(),
    create: jest.fn(),
    markVerified: jest.fn(),
    updateVerifyToken: jest.fn(),
    markDeleted: jest.fn(),
    updateSearchRadius: jest.fn(),
    updateLocationFrequency: jest.fn(),
    getPreferences: jest.fn(),
    updateUsername: jest.fn(),
    updateBiography: jest.fn(),
    updatePrivacy: jest.fn(),
    searchPublicUsers: jest.fn(),
    searchUsers: jest.fn(),
    updateLastSeen: jest.fn(),
    getOnlineStatus: jest.fn(),
    updateProfilePhoto: jest.fn(),
    getUserDetail: jest.fn(),
  },
}));

jest.mock('../../src/config/redis', () => ({
  redisClient: { set: jest.fn() },
}));

jest.mock('../../src/config/mailer', () => ({
  sendVerificationEmail: jest.fn(),
}));

jest.mock('../../src/clients/friendsClient', () => ({
  friendsClient: {
    deleteUserRelationships: jest.fn(),
  },
}));

jest.mock('bcryptjs');
jest.mock('uuid');

jest.mock('../../src/clients/aiClient', () => ({
  aiClient: {
    updateBiographyEmbedding: jest.fn().mockResolvedValue(),
  },
}));

// Supabase — mock para que los unit tests no hagan llamadas reales al storage
jest.mock('../../src/config/supabase', () => ({
  supabase: {
    storage: {
      from: jest.fn(() => ({
        upload: jest.fn().mockResolvedValue({ error: null }),
        remove: jest.fn().mockResolvedValue({ error: null }),
        getPublicUrl: jest.fn(() => ({ data: { publicUrl: 'https://test.supabase.co/storage/profile-photos/test.jpg' } })),
        createSignedUploadUrl: jest.fn().mockResolvedValue({
          data: { signedUrl: 'https://test.supabase.co/storage/v1/upload/sign/bucket/user-uuid-1-123.jpg', token: 'abc' },
          error: null,
        }),
        download: jest.fn().mockResolvedValue({ data: null, error: null }),
      })),
    },
  },
}));

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

// verifyEmail

describe('userService.verifyEmail', () => {
  beforeEach(() => jest.clearAllMocks());

  it('marca la cuenta como verificada cuando el token es válido', async () => {
    userRepository.findByVerifyToken.mockResolvedValue(USUARIO_DB);
    userRepository.markVerified.mockResolvedValue();

    await userService.verifyEmail('token-valido');

    expect(userRepository.markVerified).toHaveBeenCalledWith('user-uuid-1');
  });

  it('lanza error 400 si el token no existe o ya expiró', async () => {
    userRepository.findByVerifyToken.mockResolvedValue(null);

    await expect(userService.verifyEmail('token-vencido')).rejects.toMatchObject({ statusCode: 400 });
  });

  it('no llama a markVerified si el token es inválido', async () => {
    userRepository.findByVerifyToken.mockResolvedValue(null);

    await expect(userService.verifyEmail('token-malo')).rejects.toThrow();
    expect(userRepository.markVerified).not.toHaveBeenCalled();
  });
});

// resendVerification

describe('userService.resendVerification', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    uuidv4.mockReturnValue('nuevo-token');
    userRepository.updateVerifyToken.mockResolvedValue();
    sendVerificationEmail.mockResolvedValue();
  });

  it('genera un nuevo token y actualiza el registro del usuario', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: false });

    await userService.resendVerification('test@example.com');

    expect(userRepository.updateVerifyToken).toHaveBeenCalledWith(
      'user-uuid-1',
      'nuevo-token',
      expect.any(Date)
    );
  });

  it('normaliza el email a minúsculas antes de buscar', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: false });

    await userService.resendVerification('USER@EXAMPLE.COM');

    expect(userRepository.findByEmail).toHaveBeenCalledWith('user@example.com');
  });

  it('envía el email con el nuevo token', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: false });

    await userService.resendVerification('test@example.com');
    await Promise.resolve(); // espera el fire-and-forget

    expect(sendVerificationEmail).toHaveBeenCalledWith('test@example.com', 'nuevo-token');
  });

  it('no falla si el envío del email falla', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: false });
    sendVerificationEmail.mockRejectedValue(new Error('SMTP caído'));

    const result = await userService.resendVerification('test@example.com');
    expect(result.message).toContain('Si el correo está registrado');
  });

  it('devuelve mensaje genérico si el email no está registrado (evita enumeración)', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    const result = await userService.resendVerification('noexiste@x.com');

    expect(result.message).toContain('Si el correo está registrado');
    expect(userRepository.updateVerifyToken).not.toHaveBeenCalled();
  });

  it('devuelve mensaje genérico si la cuenta ya está verificada (evita enumeración)', async () => {
    userRepository.findByEmail.mockResolvedValue({ ...USUARIO_DB, is_verified: true });

    const result = await userService.resendVerification('test@example.com');

    expect(result.message).toContain('Si el correo está registrado');
    expect(userRepository.updateVerifyToken).not.toHaveBeenCalled();
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

  it('lanza error 410 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(userService.delete('user-uuid-1', 'Password1')).rejects.toMatchObject({ statusCode: 410 });
    expect(userRepository.markDeleted).not.toHaveBeenCalled();
  });

  it('lanza error 401 si la contraseña es incorrecta', async () => {
    bcrypt.compare.mockResolvedValue(false);

    await expect(userService.delete('user-uuid-1', 'wrong')).rejects.toMatchObject({ statusCode: 401 });
    expect(userRepository.markDeleted).not.toHaveBeenCalled();
  });

  describe('llamada al servicio friends (CA.2/CA.4)', () => {
    beforeEach(() => {
      process.env.FRIENDS_SERVICE_URL = 'http://friends-service';
      friendsClient.deleteUserRelationships.mockResolvedValue();
    });

    afterEach(() => {
      delete process.env.FRIENDS_SERVICE_URL;
    });

    it('llama a deleteUserRelationships con el userId del usuario eliminado', async () => {
      await userService.delete('user-uuid-1', 'Password1');

      expect(friendsClient.deleteUserRelationships).toHaveBeenCalledWith('user-uuid-1');
    });

    it('ejecuta el soft-delete antes de notificar a friends', async () => {
      const orden = [];
      userRepository.markDeleted.mockImplementation(() => { orden.push('markDeleted'); return Promise.resolve(); });
      friendsClient.deleteUserRelationships.mockImplementation(() => { orden.push('deleteRelationships'); return Promise.resolve(); });

      await userService.delete('user-uuid-1', 'Password1');

      expect(orden).toEqual(['markDeleted', 'deleteRelationships']);
    });

    it('no llama a friendsClient si FRIENDS_SERVICE_URL no está configurado', async () => {
      delete process.env.FRIENDS_SERVICE_URL;

      await userService.delete('user-uuid-1', 'Password1');

      expect(friendsClient.deleteUserRelationships).not.toHaveBeenCalled();
    });

    it('propaga el error si el servicio friends no está disponible', async () => {
      friendsClient.deleteUserRelationships.mockRejectedValue(new Error('Friends service error: 503'));

      await expect(userService.delete('user-uuid-1', 'Password1')).rejects.toThrow('Friends service error: 503');
    });

    it('no llama a friendsClient si la contraseña es incorrecta', async () => {
      bcrypt.compare.mockResolvedValue(false);

      await expect(userService.delete('user-uuid-1', 'wrong')).rejects.toThrow();
      expect(friendsClient.deleteUserRelationships).not.toHaveBeenCalled();
    });
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

  it('lanza error 410 si no se encuentran preferencias', async () => {
    userRepository.getPreferences.mockResolvedValue(null);

    await expect(userService.getPreferences('user-uuid-1')).rejects.toMatchObject({ statusCode: 410 });
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

  it('lanza error 410 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);
    await expect(userService.updatePreferences('user-uuid-1', { search_radius_km: 10 })).rejects.toMatchObject({ statusCode: 410 });
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
  it('lanza 410 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);

    await expect(userService.updateProfile(USER_ID, { username: 'nuevo' }))
      .rejects.toMatchObject({ statusCode: 410 });
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

// ---------------------------------------------------------------------------
// H5: userService.searchUsers — buscador público (filtra privados)
// ---------------------------------------------------------------------------
describe('userService.searchUsers', () => {
  const REQUESTER_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.searchPublicUsers.mockResolvedValue({
      users: [{ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', username: 'alice' }],
      total: 1,
      page: 1,
      limit: 20,
    });
  });

  it('delega en searchPublicUsers con los parámetros correctos', async () => {
    await userService.searchUsers(REQUESTER_ID, { q: 'ali', page: 1, limit: 20 });

    expect(userRepository.searchPublicUsers).toHaveBeenCalledWith({
      search: 'ali',
      page: 1,
      limit: 20,
      excludeUserId: REQUESTER_ID,
    });
  });

  it('devuelve la lista de usuarios públicos encontrados', async () => {
    const result = await userService.searchUsers(REQUESTER_ID, { q: 'alice' });

    expect(result.users).toHaveLength(1);
    expect(result.users[0].username).toBe('alice');
  });

  it('usa q="" por defecto si no se pasa término de búsqueda', async () => {
    await userService.searchUsers(REQUESTER_ID, {});

    expect(userRepository.searchPublicUsers).toHaveBeenCalledWith(
      expect.objectContaining({ search: '' })
    );
  });

  it('limita el limit a 50 como máximo', async () => {
    await userService.searchUsers(REQUESTER_ID, { limit: 200 });

    expect(userRepository.searchPublicUsers).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 50 })
    );
  });

  it('excluye al propio requester de los resultados (excludeUserId)', async () => {
    await userService.searchUsers(REQUESTER_ID, { q: 'ali' });

    expect(userRepository.searchPublicUsers).toHaveBeenCalledWith(
      expect.objectContaining({ excludeUserId: REQUESTER_ID })
    );
  });

  it('devuelve lista vacía si no hay resultados', async () => {
    userRepository.searchPublicUsers.mockResolvedValue({ users: [], total: 0, page: 1, limit: 20 });

    const result = await userService.searchUsers(REQUESTER_ID, { q: 'zzz' });

    expect(result.users).toEqual([]);
    expect(result.total).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// H5-friends: internalController.getBatchProfiles — endpoint interno para location service
// ---------------------------------------------------------------------------
describe('internalController.getBatchProfiles', () => {
  const USER_A = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', username: 'alice' };
  const USER_B = { id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', username: 'bob' };

  const makeReq = (body = {}) => ({ body, params: {}, query: {} });
  const makeRes = () => {
    const res = {};
    res.json = jest.fn().mockReturnValue(res);
    res.status = jest.fn().mockReturnValue(res);
    return res;
  };
  const makeNext = () => jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('llama a findProfilesByIds con los userIds del body', async () => {
    userRepository.findProfilesByIds.mockResolvedValue([USER_A, USER_B]);
    const req = makeReq({ userIds: [USER_A.id, USER_B.id] });
    const res = makeRes();

    await internalController.getBatchProfiles(req, res, makeNext());

    expect(userRepository.findProfilesByIds).toHaveBeenCalledWith([USER_A.id, USER_B.id]);
  });

  it('responde con { users: [...] } con los perfiles encontrados', async () => {
    userRepository.findProfilesByIds.mockResolvedValue([USER_A, USER_B]);
    const req = makeReq({ userIds: [USER_A.id, USER_B.id] });
    const res = makeRes();

    await internalController.getBatchProfiles(req, res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ users: [USER_A, USER_B] });
  });

  it('responde con { users: [] } si no se encuentran perfiles', async () => {
    userRepository.findProfilesByIds.mockResolvedValue([]);
    const req = makeReq({ userIds: ['no-existe-uuid'] });
    const res = makeRes();

    await internalController.getBatchProfiles(req, res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ users: [] });
  });

  it('responde con { users: [] } si userIds es un array vacío', async () => {
    userRepository.findProfilesByIds.mockResolvedValue([]);
    const req = makeReq({ userIds: [] });
    const res = makeRes();

    await internalController.getBatchProfiles(req, res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ users: [] });
  });

  it('llama a next con AppError 400 si userIds no es un array', async () => {
    const req = makeReq({ userIds: 'no-soy-array' });
    const res = makeRes();
    const next = makeNext();

    await internalController.getBatchProfiles(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(AppErrorInternal));
    expect(next.mock.calls[0][0].statusCode).toBe(400);
    expect(userRepository.findProfilesByIds).not.toHaveBeenCalled();
  });

  it('llama a next con AppError 400 si userIds es undefined', async () => {
    const req = makeReq({});
    const res = makeRes();
    const next = makeNext();

    await internalController.getBatchProfiles(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(AppErrorInternal));
    expect(next.mock.calls[0][0].statusCode).toBe(400);
  });

  it('no llama a res.json si userIds es inválido', async () => {
    const req = makeReq({ userIds: 123 });
    const res = makeRes();

    await internalController.getBatchProfiles(req, res, makeNext());

    expect(res.json).not.toHaveBeenCalled();
  });

  it('llama a next si el repository lanza un error inesperado', async () => {
    userRepository.findProfilesByIds.mockRejectedValue(new Error('DB error'));
    const req = makeReq({ userIds: [USER_A.id] });
    const res = makeRes();
    const next = makeNext();

    await internalController.getBatchProfiles(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(res.json).not.toHaveBeenCalled();
  });
});

describe('userService.searchUsersPublic', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('devuelve un array vacío si la query está vacía', async () => {
    const result = await userService.searchUsersPublic('', 'user-uuid-1');
    expect(result).toEqual([]);
    expect(userRepository.searchUsers).not.toHaveBeenCalled();
  });

  it('llama al repositorio con excludeId y onlyActive: true', async () => {
    userRepository.searchUsers.mockResolvedValue({ users: [] });

    await userService.searchUsersPublic('test', 'user-uuid-1');

    expect(userRepository.searchUsers).toHaveBeenCalledWith({
      search: 'test',
      page: 1,
      limit: 10,
      excludeId: 'user-uuid-1',
      onlyActive: true,
    });
  });

  it('mapea correctamente retornando solo campos públicos', async () => {
    userRepository.searchUsers.mockResolvedValue({
      users: [
        { id: 'uuid-1', username: 'mateo', email: 'hola@test.com', locked_until: 'algo' },
        { id: 'uuid-2', username: 'juan', email: 'juan@test.com' },
      ],
    });

    const result = await userService.searchUsersPublic('ma', 'user-uuid-99');

    expect(result).toEqual([
      { id: 'uuid-1', username: 'mateo' },
      { id: 'uuid-2', username: 'juan' },
    ]);
  });
});

// ---------------------------------------------------------------------------
// H11 CA.1: userService.heartbeat
// ---------------------------------------------------------------------------
describe('userService.heartbeat', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.getUserDetail.mockResolvedValue({ id: 'user-uuid-1', is_private: false });
    userRepository.updateLastSeen.mockResolvedValue();
  });

  it('llama a userRepository.updateLastSeen con el userId del usuario autenticado', async () => {
    await userService.heartbeat('user-uuid-1');

    expect(userRepository.updateLastSeen).toHaveBeenCalledWith('user-uuid-1');
  });

  it('llama a updateLastSeen exactamente una vez por heartbeat si el usuario no es privado', async () => {
    await userService.heartbeat('user-uuid-1');

    expect(userRepository.updateLastSeen).toHaveBeenCalledTimes(1);
  });

  it('no llama a updateLastSeen si el usuario es privado', async () => {
    userRepository.getUserDetail.mockResolvedValue({ id: 'user-uuid-1', is_private: true });

    await userService.heartbeat('user-uuid-1');

    expect(userRepository.updateLastSeen).not.toHaveBeenCalled();
  });

  it('propaga el error si updateLastSeen falla', async () => {
    userRepository.updateLastSeen.mockRejectedValue(new Error('DB error'));

    await expect(userService.heartbeat('user-uuid-1')).rejects.toThrow('DB error');
  });
});

// ---------------------------------------------------------------------------
// H11 CA.1: internalController.getOnlineStatus
// ---------------------------------------------------------------------------
describe('internalController.getOnlineStatus', () => {
  const USER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const USER_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

  const makeReq = (body = {}) => ({ body, params: {}, query: {} });
  const makeRes = () => {
    const res = {};
    res.json = jest.fn().mockReturnValue(res);
    res.status = jest.fn().mockReturnValue(res);
    return res;
  };
  const makeNext = () => jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('llama a userRepository.getOnlineStatus con los userIds del body', async () => {
    userRepository.getOnlineStatus.mockResolvedValue([USER_A]);
    const req = makeReq({ userIds: [USER_A, USER_B] });
    const res = makeRes();

    await internalController.getOnlineStatus(req, res, makeNext());

    expect(userRepository.getOnlineStatus).toHaveBeenCalledWith([USER_A, USER_B]);
  });

  it('responde con { onlineIds: [...] } con los IDs activos', async () => {
    userRepository.getOnlineStatus.mockResolvedValue([USER_A]);
    const req = makeReq({ userIds: [USER_A, USER_B] });
    const res = makeRes();

    await internalController.getOnlineStatus(req, res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ onlineIds: [USER_A] });
  });

  it('responde con { onlineIds: [] } si ninguno está online', async () => {
    userRepository.getOnlineStatus.mockResolvedValue([]);
    const req = makeReq({ userIds: [USER_A, USER_B] });
    const res = makeRes();

    await internalController.getOnlineStatus(req, res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ onlineIds: [] });
  });

  it('llama a next con AppError 400 si userIds no es un array', async () => {
    const req = makeReq({ userIds: 'no-soy-array' });
    const res = makeRes();
    const next = makeNext();

    await internalController.getOnlineStatus(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(AppErrorInternal));
    expect(next.mock.calls[0][0].statusCode).toBe(400);
    expect(userRepository.getOnlineStatus).not.toHaveBeenCalled();
  });

  it('llama a next con AppError 400 si userIds es undefined', async () => {
    const req = makeReq({});
    const res = makeRes();
    const next = makeNext();

    await internalController.getOnlineStatus(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(AppErrorInternal));
    expect(next.mock.calls[0][0].statusCode).toBe(400);
  });

  it('no llama a res.json si userIds es inválido', async () => {
    const req = makeReq({ userIds: 123 });
    const res = makeRes();

    await internalController.getOnlineStatus(req, res, makeNext());

    expect(res.json).not.toHaveBeenCalled();
  });

  it('llama a next si el repository lanza un error inesperado', async () => {
    userRepository.getOnlineStatus.mockRejectedValue(new Error('DB error'));
    const req = makeReq({ userIds: [USER_A] });
    const res = makeRes();
    const next = makeNext();

    await internalController.getOnlineStatus(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(res.json).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// H8: Foto de Perfil — Upload & Delete Tests
// ---------------------------------------------------------------------------

// Helpers para generar base64 con los magic bytes correctos
const pngBase64 = () => Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  Buffer.alloc(100),
]).toString('base64');

const jpgBase64 = () => Buffer.concat([
  Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]),
  Buffer.alloc(100),
]).toString('base64');

const elfBase64 = () => Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x00]).toString('base64');

describe('userService.uploadProfilePhoto & deleteProfilePhoto', () => {
  let supabaseMock;

  beforeEach(() => {
    jest.clearAllMocks();
    supabaseMock = require('../../src/config/supabase').supabase;
  });

  describe('userService.prepareAvatarUpload', () => {
    it('falla si el mimeType no es JPG o PNG (CA.1)', async () => {
      await expect(
        userService.prepareAvatarUpload('user-uuid-1', 'application/x-sh')
      ).rejects.toThrow('Formato inválido. Solo JPG y PNG.');
    });

    it('devuelve signedUrl y filename para mimeType válido', async () => {
      const result = await userService.prepareAvatarUpload('user-uuid-1', 'image/png');
      expect(result.signedUrl).toContain('supabase');
      expect(result.filename).toMatch(/^user-uuid-1-\d+\.png$/);
    });

    it('rechaza con 500 si Supabase falla al crear la signed URL', async () => {
      supabaseMock.storage.from.mockReturnValueOnce({
        createSignedUploadUrl: jest.fn().mockResolvedValue({ data: null, error: { message: 'Storage unavailable' } }),
      });
      await expect(
        userService.prepareAvatarUpload('user-uuid-1', 'image/jpeg')
      ).rejects.toMatchObject({ statusCode: 500 });
    });
  });

  describe('userService.confirmAvatarUpload', () => {
    const makeBlobMock = (buffer) => ({
      arrayBuffer: () => Promise.resolve(buffer),
    });

    it('falla con 403 si el filename no pertenece al usuario (CA.security)', async () => {
      await expect(
        userService.confirmAvatarUpload('user-uuid-1', 'otro-usuario-123.png')
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('falla si Supabase no encuentra el archivo subido', async () => {
      supabaseMock.storage.from.mockReturnValueOnce({
        download: jest.fn().mockResolvedValue({ data: null, error: { message: 'Not found' } }),
      });
      await expect(
        userService.confirmAvatarUpload('user-uuid-1', 'user-uuid-1-123.png')
      ).rejects.toThrow('No se encontró el archivo');
    });

    it('falla si la imagen supera los 5MB (CA.2)', async () => {
      const bigBuffer = Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        Buffer.alloc(6 * 1024 * 1024),
      ]);
      supabaseMock.storage.from.mockReturnValueOnce({
        download: jest.fn().mockResolvedValue({ data: makeBlobMock(bigBuffer), error: null }),
        remove: jest.fn().mockResolvedValue({ error: null }),
      });
      await expect(
        userService.confirmAvatarUpload('user-uuid-1', 'user-uuid-1-123.png')
      ).rejects.toThrow('La imagen no debe superar los 5MB.');
    });

    it('falla si los magic numbers no coinciden con PNG o JPG (CA.3)', async () => {
      const elfBuffer = Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x00]);
      supabaseMock.storage.from.mockReturnValueOnce({
        download: jest.fn().mockResolvedValue({ data: makeBlobMock(elfBuffer), error: null }),
        remove: jest.fn().mockResolvedValue({ error: null }),
      });
      await expect(
        userService.confirmAvatarUpload('user-uuid-1', 'user-uuid-1-123.png')
      ).rejects.toThrow('El contenido real del archivo no es JPG ni PNG.');
    });

    it('confirma exitosamente una imagen PNG y actualiza la DB (CA.1-CA.4)', async () => {
      const pngBuffer = Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(100)]);
      supabaseMock.storage.from
        .mockReturnValueOnce({ download: jest.fn().mockResolvedValue({ data: makeBlobMock(pngBuffer), error: null }) })
        .mockReturnValueOnce({ getPublicUrl: jest.fn(() => ({ data: { publicUrl: 'https://test.supabase.co/storage/profile-photos/test.jpg' } })) });
      userRepository.findProfileById.mockResolvedValue({ id: 'user-uuid-1', profile_photo_url: null });
      userRepository.updateProfilePhoto.mockResolvedValue();

      const url = await userService.confirmAvatarUpload('user-uuid-1', 'user-uuid-1-123.png');

      expect(url).toContain('supabase');
      expect(userRepository.updateProfilePhoto).toHaveBeenCalledWith('user-uuid-1', url);
    });

    it('elimina la foto anterior cuando el usuario ya tenía una (CA.5)', async () => {
      const pngBuffer = Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(100)]);
      supabaseMock.storage.from
        .mockReturnValueOnce({ download: jest.fn().mockResolvedValue({ data: makeBlobMock(pngBuffer), error: null }) })
        .mockReturnValueOnce({ getPublicUrl: jest.fn(() => ({ data: { publicUrl: 'https://test.supabase.co/storage/profile-photos/test.jpg' } })) })
        .mockReturnValueOnce({ remove: jest.fn().mockResolvedValue({ error: null }) });
      userRepository.findProfileById.mockResolvedValue({
        id: 'user-uuid-1',
        profile_photo_url: 'https://test.supabase.co/storage/v1/object/public/profile-photos/old-photo.png?v=1',
      });
      userRepository.updateProfilePhoto.mockResolvedValue();

      await userService.confirmAvatarUpload('user-uuid-1', 'user-uuid-1-123.png');

      expect(supabaseMock.storage.from).toHaveBeenCalledTimes(3);
      expect(userRepository.updateProfilePhoto).toHaveBeenCalledWith('user-uuid-1', expect.any(String));
    });
  });

  describe('userService.deleteProfilePhoto', () => {
    it('llama a Supabase remove y actualiza la DB a null si el usuario tiene foto (CA.4, CA.6)', async () => {
      userRepository.findProfileById.mockResolvedValue({
        id: 'user-uuid-1',
        profile_photo_url: 'https://test.supabase.co/storage/v1/object/public/profile-photos/old.png',
      });
      userRepository.updateProfilePhoto.mockResolvedValue();

      await userService.deleteProfilePhoto('user-uuid-1');

      expect(userRepository.updateProfilePhoto).toHaveBeenCalledWith('user-uuid-1', null);
    });

    it('actualiza la DB a null aunque el usuario no tenga foto previa', async () => {
      userRepository.findProfileById.mockResolvedValue({ id: 'user-uuid-1', profile_photo_url: null });
      userRepository.updateProfilePhoto.mockResolvedValue();

      await userService.deleteProfilePhoto('user-uuid-1');

      expect(userRepository.updateProfilePhoto).toHaveBeenCalledWith('user-uuid-1', null);
    });

    it('lanza 410 si el usuario no existe (CA.6)', async () => {
      userRepository.findProfileById.mockResolvedValue(null);

      await expect(userService.deleteProfilePhoto('no-existe')).rejects.toMatchObject({ statusCode: 410 });
      expect(userRepository.updateProfilePhoto).not.toHaveBeenCalled();
    });
  });
});

// ---------------------------------------------------------------------------
// userService.getPublicProfile
// ---------------------------------------------------------------------------
describe('userService.getPublicProfile', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('lanza error 410 si el usuario no existe', async () => {
    userRepository.getUserDetail.mockResolvedValue(null);

    await expect(userService.getPublicProfile('non-existent-id'))
      .rejects.toMatchObject({ statusCode: 410, message: 'Usuario no encontrado' });
    expect(userRepository.getUserDetail).toHaveBeenCalledWith('non-existent-id');
  });

  it('calcula is_online como true si last_seen_at es reciente (dentro de los 5 minutos)', async () => {
    const recentTime = new Date(Date.now() - 2 * 60 * 1000).toISOString(); // 2 minutos atrás
    userRepository.getUserDetail.mockResolvedValue({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      last_seen_at: recentTime,
      password_hash: 'super_secret_hash',
      email: 'sensitive@email.com',
    });

    const result = await userService.getPublicProfile('uuid-1');

    expect(result).toEqual({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      is_online: true,
      last_seen_at: recentTime,
    });
  });

  it('calcula is_online como false si last_seen_at es antiguo (mayor a 5 minutos)', async () => {
    const oldTime = new Date(Date.now() - 6 * 60 * 1000).toISOString(); // 6 minutos atrás
    userRepository.getUserDetail.mockResolvedValue({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      last_seen_at: oldTime,
      password_hash: 'super_secret_hash',
      email: 'sensitive@email.com',
    });

    const result = await userService.getPublicProfile('uuid-1');

    expect(result.is_online).toBe(false);
  });

  it('calcula is_online como false si last_seen_at es nulo', async () => {
    userRepository.getUserDetail.mockResolvedValue({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      last_seen_at: null,
      password_hash: 'super_secret_hash',
      email: 'sensitive@email.com',
    });

    const result = await userService.getPublicProfile('uuid-1');

    expect(result.is_online).toBe(false);
  });

  it('no filtra ni expone campos sensibles del usuario (solo devuelve id, username, biography, is_online, last_seen_at)', async () => {
    const recentTime = new Date().toISOString();
    userRepository.getUserDetail.mockResolvedValue({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      last_seen_at: recentTime,
      password_hash: 'super_secret_hash',
      email: 'sensitive@email.com',
      is_suspended: false,
      deleted_at: null,
      failed_login_attempts: 0,
    });

    const result = await userService.getPublicProfile('uuid-1');

    expect(result).toEqual({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      is_online: true,
      last_seen_at: recentTime,
    });

    expect(result.password_hash).toBeUndefined();
    expect(result.email).toBeUndefined();
    expect(result.is_suspended).toBeUndefined();
    expect(result.deleted_at).toBeUndefined();
    expect(result.failed_login_attempts).toBeUndefined();
  });

  it('calcula is_online como false y mantiene last_seen_at si el usuario es privado (Modo Fantasma) aunque la ultima conexion sea reciente', async () => {
    const recentTime = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    userRepository.getUserDetail.mockResolvedValue({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      last_seen_at: recentTime,
      is_private: true,
      password_hash: 'super_secret_hash',
      email: 'sensitive@email.com',
    });

    const result = await userService.getPublicProfile('uuid-1');

    expect(result).toEqual({
      id: 'uuid-1',
      username: 'mateo',
      biography: 'Hola udesa',
      is_online: false,
      last_seen_at: recentTime,
    });
  });
});

