const { Router } = require('express');
const { userController } = require('./user.controller');
const { validate } = require('../../middlewares/validate');
const { authenticate } = require('../../middlewares/authenticate');
const { registerSchema, resendVerificationSchema, deleteSchema, updatePreferencesSchema } = require('./user.schemas');

const router = Router();

// POST /api/users/register
router.post('/register', validate(registerSchema), userController.register);

// GET /api/users/verify-email?token=<uuid>
router.get('/verify-email', userController.verifyEmail);

// POST /api/users/resend-verification
router.post(
  '/resend-verification',
  validate(resendVerificationSchema),
  userController.resendVerification
);
// CA.3: requiere JWT (usuario logueado) + confirmación de contraseña en el body
router.post('/delete', authenticate, validate(deleteSchema), userController.delete);

// Preferencias
router.get('/preferences', authenticate, userController.getPreferences);
router.patch(
  '/preferences',
  authenticate,
  validate(updatePreferencesSchema),
  userController.updatePreferences
);

module.exports = router;
