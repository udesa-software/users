const { Router } = require('express');
const { internalController } = require('./internal.controller');

const router = Router();

router.post('/users/profiles', internalController.getBatchProfiles);
router.get('/users', internalController.listUsers);
router.get('/users/:id', internalController.getUser);
router.patch('/users/:id/privacy', internalController.updatePrivacy);
router.get('/users/:id/preferences', internalController.getPreferences);
router.post('/users/:id/suspend', internalController.suspendUser);
router.post('/users/:id/unsuspend', internalController.unsuspendUser);
router.get('/metrics', internalController.getMetrics);

module.exports = router;
