const { Router } = require('express');
const { authController } = require('./auth.controller');
const { validate } = require('../../middlewares/validate');
const { loginSchema, forgotPasswordSchema, resetPasswordSchema, changePasswordSchema } = require('./auth.schemas');
const { authenticate } = require('../../middlewares/authenticate');

const router = Router();

// POST /api/auth/login
router.post('/login', validate(loginSchema), authController.login);

// POST /api/auth/forgot-password
router.post('/forgot-password', validate(forgotPasswordSchema), authController.forgotPassword);

// POST /api/auth/reset-password
router.post('/reset-password', validate(resetPasswordSchema), authController.resetPassword);

// GET /api/auth/reset-password?token=<uuid>
router.get('/reset-password', authController.verifyResetToken);

// POST /api/auth/change-password
router.post('/change-password', authenticate, validate(changePasswordSchema), authController.changePassword);

module.exports = router;
