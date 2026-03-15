const { z } = require('zod');

const loginSchema = z.object({
  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),

  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

module.exports = { loginSchema };
