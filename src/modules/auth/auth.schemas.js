const { z } = require('zod');

const loginSchema = z.object({
  identifier: z
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

const changePasswordSchema = z.object({
  currentPassword: z
    .string({ required_error: 'La contraseña actual es obligatoria' })
    .min(1, 'La contraseña actual es obligatoria'),

  newPassword: z
    .string({ required_error: 'La nueva contraseña es obligatoria' })
    .min(8, 'La nueva contraseña debe tener al menos 8 caracteres')
    .regex(/[A-Z]/, 'La nueva contraseña debe tener al menos una letra mayúscula')
    .regex(/[0-9]/, 'La nueva contraseña debe tener al menos un número'),

  confirmPassword: z
    .string({ required_error: 'La confirmación de la nueva contraseña es obligatoria' }),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: 'Las contraseñas no coinciden',
  path: ['confirmPassword'],
});

const resendVerificationSchema = z.object({
  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),
});

module.exports = { loginSchema, forgotPasswordSchema, resetPasswordSchema, changePasswordSchema, resendVerificationSchema };
