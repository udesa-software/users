const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { userRepository } = require('../users/user.repository');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

const authService = {
  async login({ email, password }) {
    const user = await userRepository.findByEmail(email.toLowerCase());

    // Use the same generic error for both "user not found" and "wrong password"
    // to avoid user enumeration
    if (!user) {
      throw new AppError(401, 'Email o contraseña incorrectos');
    }

    if (!user.is_verified) {
      throw new AppError(403, 'Debés verificar tu email antes de iniciar sesión');
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      throw new AppError(401, 'Email o contraseña incorrectos');
    }

    if(user.is_deleted){
      throw new AppError(401, 'Tu cuenta fue eliminada');
    }

    const token = jwt.sign(
      { sub: user.id, username: user.username, email: user.email },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    return {
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        is_verified: user.is_verified,
        created_at: user.created_at,
      },
    };
  },
};

module.exports = { authService };
