const { z } = require('zod');

const loginSchema = z.object({
  email_or_username: z
    .string({ required_error: 'El email o nombre de usuario es obligatorio' })
    .min(1, 'El email o nombre de usuario es obligatorio'),

  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

const forgotPasswordSchema = z.object({
  identifier: z
    .string({ required_error: 'El email o nombre de usuario es obligatorio' })
    .min(1, 'El email o nombre de usuario es obligatorio'),
});

const resetPasswordSchema = z.object({
  token: z
    .string({ required_error: 'El token es obligatorio' })
    .uuid('El formato del token no es válido'),
  
  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .regex(/[A-Z]/, 'La contraseña debe tener al menos una letra mayúscula')
    .regex(/[0-9]/, 'La contraseña debe tener al menos un número'),

  confirmPassword: z
    .string({ required_error: 'La confirmación de la contraseña es obligatoria' }),
});

module.exports = { loginSchema, forgotPasswordSchema, resetPasswordSchema };
