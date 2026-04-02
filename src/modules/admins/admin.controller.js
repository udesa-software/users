const { adminService } = require('./admin.service');

const adminController = {
  async create(req, res, next) {
    try {
      const admin = await adminService.createAdmin(req.body, req.admin.sub);
      res.status(201).json({
        message: 'Administrador creado exitosamente. Se envió la contraseña temporal por email.',
        admin,
      });
    } catch (err) {
      next(err);
    }
  },

  async resetPassword(req, res, next) {
    try {
      const result = await adminService.resetAdminPassword(req.params.id, req.admin.sub);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { adminController };
