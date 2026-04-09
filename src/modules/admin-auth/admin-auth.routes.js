const { Router } = require('express');
const { adminAuthController } = require('./admin-auth.controller');
const { validate } = require('../../middlewares/validate');
const { authenticateAdmin } = require('../../middlewares/authenticateAdmin');
const { loginSchema, changePasswordSchema } = require('./admin-auth.schemas');

const router = Router();

// POST /api/admin/auth/login — H2
router.post('/login', validate(loginSchema), adminAuthController.login);

// POST /api/admin/auth/refresh — get new access token using refresh token cookie
router.post('/refresh', adminAuthController.refresh);

// POST /api/admin/auth/logout
router.post('/logout', authenticateAdmin, adminAuthController.logout);

// POST /api/admin/auth/change-password — H1 CA.1
// Solo requiere authenticateAdmin, NO requirePasswordChanged (es justamente para cumplirlo)
router.post('/change-password', authenticateAdmin, validate(changePasswordSchema), adminAuthController.changePassword);

module.exports = router;
