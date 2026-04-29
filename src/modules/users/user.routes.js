const { Router } = require('express');
const { userController } = require('./user.controller');
const { validate } = require('../../middlewares/validate');
const { authenticate } = require('../../middlewares/authenticate');
const { registerSchema, deleteSchema, updatePreferencesSchema, updateProfileSchema} = require('./user.schemas');

const router = Router();

// POST /api/users/register
router.post('/register', validate(registerSchema), userController.register);

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

router.patch('/profile', authenticate, validate(updateProfileSchema), userController.updateProfile);

// H1 E.2: búsqueda de usuarios públicos para agregar amigos (excluye privados)
router.get('/search', authenticate, userController.searchUsers);

module.exports = router;
