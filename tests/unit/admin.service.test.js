const bcrypt = require('bcryptjs');
const { adminService } = require('../../src/modules/admins/admin.service');
const { adminRepository } = require('../../src/modules/admins/admin.repository');
const { sendTempPasswordEmail } = require('../../src/config/mailer');
const { env } = require('../../src/config/env');

jest.mock('../../src/modules/admins/admin.repository', () => ({
  adminRepository: {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
    updateTempPassword: jest.fn(),
  },
}));

jest.mock('../../src/config/mailer', () => ({
  sendTempPasswordEmail: jest.fn(),
}));

jest.mock('../../src/config/env', () => ({ env: { ALLOWED_EMAIL_DOMAIN: undefined } }));

jest.mock('bcryptjs');
jest.mock('uuid', () => ({ v4: () => 'aaaabbbbccccddddeeeeffffgggghhhh' }));

const ADMIN_DB = {
  id: 'admin-uuid-2',
  email: 'mod@udesa.edu.ar',
  role: 'moderator',
  must_change_password: true,
  created_at: new Date().toISOString(),
};

// createAdmin
describe('adminService.createAdmin', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.findByEmail.mockResolvedValue(null);
    adminRepository.create.mockResolvedValue(ADMIN_DB);
    bcrypt.hash.mockResolvedValue('hashed-temp-password');
    sendTempPasswordEmail.mockResolvedValue();
  });

  it('crea el admin y devuelve sus datos con la contraseña temporal', async () => {
    const result = await adminService.createAdmin(
      { email: 'mod@udesa.edu.ar', role: 'moderator' },
      'superadmin-uuid'
    );

    expect(adminRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'mod@udesa.edu.ar', role: 'moderator' })
    );
    expect(result.temp_password).toBeDefined();
    expect(result.temp_password_expires_at).toBeDefined();
  });

  it('hashea la contraseña temporal con bcrypt', async () => {
    await adminService.createAdmin(
      { email: 'mod@udesa.edu.ar', role: 'moderator' },
      'superadmin-uuid'
    );

    expect(bcrypt.hash).toHaveBeenCalledWith(expect.any(String), 12);
  });

  it('envía email con la contraseña temporal (fire-and-forget)', async () => {
    await adminService.createAdmin(
      { email: 'mod@udesa.edu.ar', role: 'moderator' },
      'superadmin-uuid'
    );
    await Promise.resolve();

    expect(sendTempPasswordEmail).toHaveBeenCalledWith(
      'mod@udesa.edu.ar',
      expect.any(String)
    );
  });

  it('no falla si el envío del email falla', async () => {
    sendTempPasswordEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(
      adminService.createAdmin({ email: 'mod@udesa.edu.ar', role: 'moderator' }, 'superadmin-uuid')
    ).resolves.toBeDefined();
  });

  it('lanza error 409 si el email ya está en uso', async () => {
    adminRepository.findByEmail.mockResolvedValue(ADMIN_DB);

    await expect(
      adminService.createAdmin({ email: 'mod@udesa.edu.ar', role: 'moderator' }, 'superadmin-uuid')
    ).rejects.toMatchObject({ statusCode: 409 });
    expect(adminRepository.create).not.toHaveBeenCalled();
  });

  it('lanza error 400 si el email no pertenece al dominio permitido', async () => {
    env.ALLOWED_EMAIL_DOMAIN = 'udesa.edu.ar';

    await expect(
      adminService.createAdmin({ email: 'mod@gmail.com', role: 'moderator' }, 'superadmin-uuid')
    ).rejects.toMatchObject({ statusCode: 400 });
    expect(adminRepository.create).not.toHaveBeenCalled();

    env.ALLOWED_EMAIL_DOMAIN = undefined;
  });

  it('acepta el email si pertenece al dominio permitido', async () => {
    env.ALLOWED_EMAIL_DOMAIN = 'udesa.edu.ar';

    const result = await adminService.createAdmin(
      { email: 'mod@udesa.edu.ar', role: 'moderator' },
      'superadmin-uuid'
    );

    expect(result).toBeDefined();
    env.ALLOWED_EMAIL_DOMAIN = undefined;
  });
});

// resetAdminPassword
describe('adminService.resetAdminPassword', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    adminRepository.findById.mockResolvedValue(ADMIN_DB);
    adminRepository.updateTempPassword.mockResolvedValue();
    bcrypt.hash.mockResolvedValue('hashed-temp-password');
    sendTempPasswordEmail.mockResolvedValue();
  });

  it('regenera la contraseña temporal y la devuelve', async () => {
    const result = await adminService.resetAdminPassword('admin-uuid-2', 'superadmin-uuid');

    expect(adminRepository.updateTempPassword).toHaveBeenCalledWith(
      'admin-uuid-2',
      'hashed-temp-password',
      expect.any(Date)
    );
    expect(result.temp_password).toBeDefined();
    expect(result.message).toBeDefined();
  });

  it('envía email con la nueva contraseña temporal', async () => {
    await adminService.resetAdminPassword('admin-uuid-2', 'superadmin-uuid');
    await Promise.resolve();

    expect(sendTempPasswordEmail).toHaveBeenCalledWith('mod@udesa.edu.ar', expect.any(String));
  });

  it('lanza error 404 si el admin no existe', async () => {
    adminRepository.findById.mockResolvedValue(null);

    await expect(
      adminService.resetAdminPassword('admin-uuid-2', 'superadmin-uuid')
    ).rejects.toMatchObject({ statusCode: 404 });
    expect(adminRepository.updateTempPassword).not.toHaveBeenCalled();
  });

  it('lanza error 400 si intenta resetear su propia contraseña', async () => {
    await expect(
      adminService.resetAdminPassword('admin-uuid-2', 'admin-uuid-2')
    ).rejects.toMatchObject({ statusCode: 400 });
    expect(adminRepository.updateTempPassword).not.toHaveBeenCalled();
  });

  it('no falla si el envío del email falla en resetAdminPassword', async () => {
    sendTempPasswordEmail.mockRejectedValue(new Error('SMTP caído'));

    await expect(
      adminService.resetAdminPassword('admin-uuid-2', 'superadmin-uuid')
    ).resolves.toBeDefined();
  });
});
