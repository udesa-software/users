const { Router } = require('express');
const { userController } = require('./user.controller');
const { validate } = require('../../middlewares/validate');
const { authenticate } = require('../../middlewares/authenticate');
const { registerSchema, deleteSchema, updatePreferencesSchema, updateProfileSchema } = require('./user.schemas');

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
// búsqueda pública simplificada (solo id+username, para uso en friends/otros servicios)
router.get('/search/public', authenticate, userController.searchUsersPublic);

// H10 CA.1: heartbeat — actualiza last_seen_at para el tracking de presencia online.
// La app móvil lo llama en background cada ~60s mientras está en uso.
router.post('/heartbeat', authenticate, userController.heartbeat);

// H8: Foto de perfil — subida y borrado
router.post('/profile-photo', authenticate, userController.uploadProfilePhoto);
router.delete('/profile-photo', authenticate, userController.deleteProfilePhoto);
// GET /api/users/:id/profile — perfil público de cualquier usuario autenticado
router.get('/:id/profile', authenticate, userController.getPublicProfile);

module.exports = router;
