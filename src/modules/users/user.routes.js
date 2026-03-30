const { Router } = require('express');
const { userController } = require('./user.controller');
const { validate } = require('../../middlewares/validate');
const { authenticate } = require('../../middlewares/authenticate');
const { registerSchema, deleteSchema } = require('./user.schemas');

const router = Router();

// POST /api/users/register
router.post('/register', validate(registerSchema), userController.register);

// GET /api/users/verify-email?token=<uuid>
router.get('/verify-email', userController.verifyEmail);

// CA.3: requiere JWT (usuario logueado) + confirmación de contraseña en el body
router.post('/delete', authenticate, validate(deleteSchema), userController.delete);

module.exports = router;
