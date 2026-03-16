const { Router } = require('express');
const { authController } = require('./auth.controller');
const { validate } = require('../../middlewares/validate');
const { loginSchema } = require('./auth.schemas');

const router = Router();

// POST /api/auth/login
router.post('/login', validate(loginSchema), authController.login);

module.exports = router;
