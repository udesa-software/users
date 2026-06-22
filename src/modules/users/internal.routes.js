const { Router } = require('express');
const { internalController } = require('./internal.controller');
const { authenticateInternal } = require('../../middlewares/authenticateInternal');

const router = Router();

router.post('/users/profiles', internalController.getBatchProfiles);
router.get('/users', internalController.listUsers);
router.get('/users/:id', internalController.getUser);
router.patch('/users/:id/privacy', internalController.updatePrivacy);
router.get('/users/:id/preferences', internalController.getPreferences);
router.post('/users/:id/suspend', internalController.suspendUser);
router.post('/users/:id/unsuspend', internalController.unsuspendUser);
// H9: solo estas dos rutas nuevas exigen el secreto interno (gap preexistente en el resto)
router.post('/users/:id/flag-review', authenticateInternal, internalController.flagReview);
router.post('/users/:id/resolve-review', authenticateInternal, internalController.resolveReview);
router.get('/metrics', internalController.getMetrics);
router.post('/users/online-status', internalController.getOnlineStatus);
router.post('/users/candidates', internalController.getCandidates);

module.exports = router;
