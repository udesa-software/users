const { userController } = require('../../src/modules/users/user.controller');
const { userService } = require('../../src/modules/users/user.service');

jest.mock('../../src/modules/users/user.service', () => ({
  userService: {
    register: jest.fn(),
    delete: jest.fn(),
    getPreferences: jest.fn(),
    updatePreferences: jest.fn(),
    searchUsers: jest.fn(),
    updateProfile: jest.fn(),
    searchUsersPublic: jest.fn(),
    heartbeat: jest.fn(),
    prepareAvatarUpload: jest.fn(),
    confirmAvatarUpload: jest.fn(),
    deleteProfilePhoto: jest.fn(),
    getPublicProfile: jest.fn(),
  },
}));

const makeReq = ({ body = {}, params = {}, query = {}, user = { sub: 'user-uuid-1' } } = {}) =>
  ({ body, params, query, user });

const makeRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  return res;
};

const makeNext = () => jest.fn();

beforeEach(() => jest.clearAllMocks());

// ---------------------------------------------------------------------------
describe('userController.register', () => {
  it('responde 201 con el usuario creado', async () => {
    const fakeUser = { id: 'u1', username: 'tomas' };
    userService.register.mockResolvedValue(fakeUser);
    const res = makeRes();

    await userController.register(makeReq({ body: { username: 'tomas' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ user: fakeUser }));
  });

  it('llama a next si el service lanza error', async () => {
    userService.register.mockRejectedValue(new Error('duplicate'));
    const next = makeNext();

    await userController.register(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.delete', () => {
  it('responde 200 con mensaje de confirmación', async () => {
    userService.delete.mockResolvedValue();
    const res = makeRes();

    await userController.delete(makeReq({ body: { password: 'pass123' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: expect.any(String) }));
  });

  it('llama a next si el service lanza error', async () => {
    userService.delete.mockRejectedValue(new Error('wrong password'));
    const next = makeNext();

    await userController.delete(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.getPreferences', () => {
  it('responde 200 con las preferencias', async () => {
    const fakePrefs = { search_radius_km: 10 };
    userService.getPreferences.mockResolvedValue(fakePrefs);
    const res = makeRes();

    await userController.getPreferences(makeReq(), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(fakePrefs);
  });

  it('llama a next si el service lanza error', async () => {
    userService.getPreferences.mockRejectedValue(new Error('not found'));
    const next = makeNext();

    await userController.getPreferences(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.updatePreferences', () => {
  it('responde 200 con las preferencias actualizadas', async () => {
    const fakePrefs = { search_radius_km: 20 };
    userService.updatePreferences.mockResolvedValue(fakePrefs);
    const res = makeRes();

    await userController.updatePreferences(makeReq({ body: { search_radius_km: 20 } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ preferences: fakePrefs }));
  });

  it('llama a next si el service lanza error', async () => {
    userService.updatePreferences.mockRejectedValue(new Error('bad data'));
    const next = makeNext();

    await userController.updatePreferences(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.searchUsers', () => {
  it('responde con el resultado de la búsqueda', async () => {
    const fakeResult = { users: [], total: 0 };
    userService.searchUsers.mockResolvedValue(fakeResult);
    const res = makeRes();

    await userController.searchUsers(makeReq({ query: { q: 'tomas', page: 1, limit: 10 } }), res, makeNext());

    expect(res.json).toHaveBeenCalledWith(fakeResult);
  });

  it('llama a next si el service lanza error', async () => {
    userService.searchUsers.mockRejectedValue(new Error('db error'));
    const next = makeNext();

    await userController.searchUsers(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.updateProfile', () => {
  it('responde 200 con los campos actualizados', async () => {
    const fakeUpdates = { username: 'nuevonombre' };
    userService.updateProfile.mockResolvedValue(fakeUpdates);
    const res = makeRes();

    await userController.updateProfile(makeReq({ body: { username: 'nuevonombre' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(fakeUpdates);
  });

  it('llama a next si el service lanza error', async () => {
    userService.updateProfile.mockRejectedValue(new Error('conflict'));
    const next = makeNext();

    await userController.updateProfile(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.searchUsersPublic', () => {
  it('responde 200 con la lista de usuarios', async () => {
    const fakeUsers = [{ id: 'u1', username: 'tomas' }];
    userService.searchUsersPublic.mockResolvedValue(fakeUsers);
    const res = makeRes();

    await userController.searchUsersPublic(makeReq({ query: { username: 'tomas' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(fakeUsers);
  });

  it('llama a next si el service lanza error', async () => {
    userService.searchUsersPublic.mockRejectedValue(new Error('db error'));
    const next = makeNext();

    await userController.searchUsersPublic(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.heartbeat', () => {
  it('responde 204 sin body', async () => {
    userService.heartbeat.mockResolvedValue();
    const res = makeRes();

    await userController.heartbeat(makeReq(), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.send).toHaveBeenCalled();
  });

  it('llama a next si el service lanza error', async () => {
    userService.heartbeat.mockRejectedValue(new Error('error'));
    const next = makeNext();

    await userController.heartbeat(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.prepareAvatarUpload', () => {
  it('responde 200 con signedUrl y filename', async () => {
    const fakeResult = { signedUrl: 'https://supabase.co/sign/test.jpg', filename: 'user-uuid-1-123.jpg' };
    userService.prepareAvatarUpload.mockResolvedValue(fakeResult);
    const res = makeRes();

    await userController.prepareAvatarUpload(makeReq({ body: { mimeType: 'image/jpeg' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(fakeResult);
  });

  it('llama a next si el service lanza error', async () => {
    userService.prepareAvatarUpload.mockRejectedValue(new Error('formato inválido'));
    const next = makeNext();

    await userController.prepareAvatarUpload(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.confirmAvatarUpload', () => {
  it('responde 200 con profile_photo_url', async () => {
    const fakeUrl = 'https://supabase.co/storage/profile-photos/user-uuid-1-123.jpg';
    userService.confirmAvatarUpload.mockResolvedValue(fakeUrl);
    const res = makeRes();

    await userController.confirmAvatarUpload(makeReq({ body: { filename: 'user-uuid-1-123.jpg' } }), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ profile_photo_url: fakeUrl });
  });

  it('llama a next si el service lanza error', async () => {
    userService.confirmAvatarUpload.mockRejectedValue(new Error('archivo no encontrado'));
    const next = makeNext();

    await userController.confirmAvatarUpload(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.deleteProfilePhoto', () => {
  it('responde 200 con mensaje de confirmación', async () => {
    userService.deleteProfilePhoto.mockResolvedValue();
    const res = makeRes();

    await userController.deleteProfilePhoto(makeReq(), res, makeNext());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: expect.any(String) }));
  });

  it('llama a next si el service lanza error', async () => {
    userService.deleteProfilePhoto.mockRejectedValue(new Error('not found'));
    const next = makeNext();

    await userController.deleteProfilePhoto(makeReq(), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});

// ---------------------------------------------------------------------------
describe('userController.getPublicProfile', () => {
  it('responde con el perfil público del usuario', async () => {
    const fakeProfile = { id: 'u1', username: 'tomas', biography: '', is_online: false };
    userService.getPublicProfile.mockResolvedValue(fakeProfile);
    const res = makeRes();

    await userController.getPublicProfile(makeReq({ params: { id: 'u1' } }), res, makeNext());

    expect(res.json).toHaveBeenCalledWith(fakeProfile);
  });

  it('llama a next si el service lanza error', async () => {
    userService.getPublicProfile.mockRejectedValue(new Error('not found'));
    const next = makeNext();

    await userController.getPublicProfile(makeReq({ params: { id: 'no-existe' } }), makeRes(), next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});
