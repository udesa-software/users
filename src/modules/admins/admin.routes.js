const { Router } = require('express');
const { adminController } = require('./admin.controller');
const { validate } = require('../../middlewares/validate');
const { authenticateAdmin } = require('../../middlewares/authenticateAdmin');
const { authorize, requirePasswordChanged } = require('../../middlewares/authorize');
const { createAdminSchema } = require('./admin.schemas');

const router = Router();

// Todas las rutas requieren: estar logueado + haber cambiado la contraseña + ser SuperAdmin
router.use(authenticateAdmin, requirePasswordChanged, authorize('superadmin'));

// POST /api/admin/admins — H1: crear nuevo administrador
router.post('/', validate(createAdminSchema), adminController.create);

// POST /api/admin/admins/:id/reset-password — H1 CA.3: regenerar contraseña temporal expirada
router.post('/:id/reset-password', adminController.resetPassword);

module.exports = router;
