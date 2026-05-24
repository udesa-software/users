const { env } = require('../config/env');

const notificationsClient = {
  async clearToken(userId) {
    if (!env.NOTIFICATIONS_SERVICE_URL) return;

    try {
      const url = `${env.NOTIFICATIONS_SERVICE_URL}/tokens/${userId}`;
      const response = await fetch(url, {
        method: 'DELETE',
        headers: {
          'x-internal-secret': env.INTERNAL_SECRET,
        },
      });

      if (!response.ok) {
        console.error(`[NotificationsClient] Failed to clear token: ${response.statusText}`);
      }
    } catch (error) {
      console.error('[NotificationsClient] Error calling notifications service:', error.message);
    }
  },
};

module.exports = { notificationsClient };
