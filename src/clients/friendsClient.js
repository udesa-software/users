// H4 CA.2/CA.4: cliente HTTP para notificar al servicio de friends que elimine
// todas las relaciones (aceptadas y pendientes) de un usuario eliminado.

const friendsClient = {
  /**
   * Elimina lógicamente todas las relaciones de amistad del usuario dado.
   * @param {string} userId
   */
  async deleteUserRelationships(userId) {
    const url = `${process.env.FRIENDS_SERVICE_URL}/api/friends/user/${userId}`;
    const response = await fetch(url, { method: 'DELETE' });

    if (!response.ok) {
      throw new Error(`Friends service error: ${response.status}`);
    }
  },
};

module.exports = { friendsClient };