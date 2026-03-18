const { z } = require('zod');

const loginSchema = z.object({
  email_or_username: z
    .string({ required_error: 'El email o usuario es obligatorio' })
    .min(1, 'El email o usuario es obligatorio'),

  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

module.exports = { loginSchema };
