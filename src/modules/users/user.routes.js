const { Router } = require('express');
const { userController } = require('./user.controller');
const { validate } = require('../../middlewares/validate');
const { registerSchema, resendVerificationSchema } = require('./user.schemas');

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

module.exports = router;
