const { internalController } = require('../../src/modules/users/internal.controller');
const { userRepository } = require('../../src/modules/users/user.repository');
const { redisClient } = require('../../src/config/redis');
const { notificationsClient } = require('../../src/clients/notificationsClient');

jest.mock('../../src/modules/users/user.repository', () => ({
  userRepository: {
    findById: jest.fn(),
    flagUnderReview: jest.fn(),
    clearUnderReview: jest.fn(),
    deleteAllRefreshTokensForUser: jest.fn(),
    getUnderReviewResolvedAt: jest.fn(),
    exportUsers: jest.fn(),
  },
}));

jest.mock('../../src/config/redis', () => ({
  redisClient: { set: jest.fn().mockResolvedValue('OK') },
}));

jest.mock('../../src/clients/notificationsClient', () => ({
  notificationsClient: { clearToken: jest.fn() },
}));

const USER_ID = 'user-uuid-1';

function makeReq(overrides = {}) {
  return { params: { id: USER_ID }, body: {}, ...overrides };
}
function makeRes() {
  return { json: jest.fn() };
}
function makeNext() {
  return jest.fn();
}

describe('internalController.flagReview', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.deleteAllRefreshTokensForUser.mockResolvedValue();
  });

  it('devuelve 410 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);
    const next = makeNext();
    await internalController.flagReview(makeReq(), makeRes(), next);
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 410 }));
  });

  it('es idempotente: si ya está en revisión, no vuelve a revocar tokens', async () => {
    userRepository.findById.mockResolvedValue({ id: USER_ID, under_review: true });
    const res = makeRes();
    await internalController.flagReview(makeReq(), res, makeNext());
    expect(userRepository.flagUnderReview).not.toHaveBeenCalled();
    expect(userRepository.deleteAllRefreshTokensForUser).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ message: 'El usuario ya está en revisión.' });
  });

  it('marca en revisión, revoca refresh tokens y publica la revocación en Redis (CA.4)', async () => {
    userRepository.findById.mockResolvedValue({ id: USER_ID, under_review: false });
    userRepository.flagUnderReview.mockResolvedValue({ token_version: 2 });
    const res = makeRes();

    await internalController.flagReview(makeReq(), res, makeNext());

    expect(userRepository.flagUnderReview).toHaveBeenCalledWith(USER_ID);
    expect(userRepository.deleteAllRefreshTokensForUser).toHaveBeenCalledWith(USER_ID);
    expect(redisClient.set).toHaveBeenCalledWith(`revoked:${USER_ID}`, 2, 'EX', 15 * 60);
    expect(notificationsClient.clearToken).toHaveBeenCalledWith(USER_ID);
    expect(res.json).toHaveBeenCalledWith({ message: 'Usuario marcado en revisión. Su sesión fue invalidada.' });
  });
});

describe('internalController.resolveReview', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('devuelve 410 si el usuario no existe', async () => {
    userRepository.findById.mockResolvedValue(null);
    const next = makeNext();
    await internalController.resolveReview(makeReq(), makeRes(), next);
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 410 }));
  });

  it('devuelve 400 si el usuario no está en revisión', async () => {
    userRepository.findById.mockResolvedValue({ id: USER_ID, under_review: false });
    const next = makeNext();
    await internalController.resolveReview(makeReq(), makeRes(), next);
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 400, message: 'El usuario no está en revisión' })
    );
  });

  it('limpia el estado de revisión y devuelve el mensaje de éxito', async () => {
    userRepository.findById.mockResolvedValue({ id: USER_ID, under_review: true });
    const res = makeRes();

    await internalController.resolveReview(makeReq(), res, makeNext());

    expect(userRepository.clearUnderReview).toHaveBeenCalledWith(USER_ID);
    expect(res.json).toHaveBeenCalledWith({
      message: 'Revisión resuelta. El usuario puede volver a iniciar sesión.',
    });
  });
});

describe('internalController.getReviewStatus', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('devuelve underReviewResolvedAt cuando el usuario ya fue resuelto antes', async () => {
    const resolvedAt = '2026-06-22T10:00:00.000Z';
    userRepository.getUnderReviewResolvedAt.mockResolvedValue(resolvedAt);
    const res = makeRes();

    await internalController.getReviewStatus(makeReq(), res, makeNext());

    expect(userRepository.getUnderReviewResolvedAt).toHaveBeenCalledWith(USER_ID);
    expect(res.json).toHaveBeenCalledWith({ underReviewResolvedAt: resolvedAt });
  });

  it('devuelve underReviewResolvedAt null cuando la cuenta nunca fue resuelta', async () => {
    userRepository.getUnderReviewResolvedAt.mockResolvedValue(null);
    const res = makeRes();

    await internalController.getReviewStatus(makeReq(), res, makeNext());

    expect(res.json).toHaveBeenCalledWith({ underReviewResolvedAt: null });
  });

  it('llama a next con el error si el repositorio rechaza', async () => {
    userRepository.getUnderReviewResolvedAt.mockRejectedValue(new Error('DB error'));
    const next = makeNext();

    await internalController.getReviewStatus(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// H8: exportar lista completa para CSV
describe('internalController.exportUsers', () => {
  const mockUsers = [
    { id: 'uuid-1', username: 'alice', email: 'alice@test.com', is_verified: true, is_suspended: false, under_review: false, deleted_at: null, created_at: '2026-01-01T00:00:00Z' },
    { id: 'uuid-2', username: 'bob',   email: 'bob@test.com',   is_verified: false, is_suspended: true,  under_review: false, deleted_at: null, created_at: '2026-02-01T00:00:00Z' },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    userRepository.exportUsers.mockResolvedValue(mockUsers);
  });

  it('llama a userRepository.exportUsers con el search recibido', async () => {
    const req = { query: { search: 'alice' } };
    await internalController.exportUsers(req, makeRes(), makeNext());
    expect(userRepository.exportUsers).toHaveBeenCalledWith({ search: 'alice' });
  });

  it('usa string vacío si no se pasa search', async () => {
    const req = { query: {} };
    await internalController.exportUsers(req, makeRes(), makeNext());
    expect(userRepository.exportUsers).toHaveBeenCalledWith({ search: '' });
  });

  it('devuelve el array de usuarios en { users }', async () => {
    const req = { query: {} };
    const res = makeRes();
    await internalController.exportUsers(req, res, makeNext());
    expect(res.json).toHaveBeenCalledWith({ users: mockUsers });
  });

  it('llama a next con el error si el repositorio rechaza', async () => {
    userRepository.exportUsers.mockRejectedValue(new Error('DB error'));
    const req = { query: {} };
    const next = makeNext();
    await internalController.exportUsers(req, makeRes(), next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});
