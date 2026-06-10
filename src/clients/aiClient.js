const { env } = require('../config/env');

const aiClient = {
  /**
   * Notifica al ai-service para que pre-compute y guarde el embedding de la biografía del usuario.
   * Fire-and-forget: no bloquea el update de perfil si falla.
   * @param {string} userId
   * @param {string} biography
   */
  async updateBiographyEmbedding(userId, biography) {
    if (!env.AI_SERVICE_URL) return;

    try {
      const url = `${env.AI_SERVICE_URL}/api/ai/internal/embedding`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-internal-secret': env.INTERNAL_SECRET,
        },
        body: JSON.stringify({ user_id: userId, biography }),
      });

      if (!response.ok) {
        console.error(`[AIClient] Failed to update biography embedding: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('[AIClient] Error calling AI service:', error.message);
    }
  },
};

module.exports = { aiClient };
