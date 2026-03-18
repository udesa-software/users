const { Router } = require('express');
const { authController } = require('./auth.controller');
const { validate } = require('../../middlewares/validate');
const { loginSchema, forgotPasswordSchema, resetPasswordSchema } = require('./auth.schemas');

const router = Router();

// POST /api/auth/login
router.post('/login', validate(loginSchema), authController.login);

// POST /api/auth/forgot-password
router.post('/forgot-password', validate(forgotPasswordSchema), authController.forgotPassword);

// POST /api/auth/reset-password
router.post('/reset-password', validate(resetPasswordSchema), authController.resetPassword);

module.exports = router;
