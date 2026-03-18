const { z } = require('zod');

// CA.2: valid email format
// CA.3: username 4-15 chars, alphanumeric only, unique (uniqueness checked in service)
// CA.4: password min 8 chars, 1 uppercase, 1 number
// CA.5: all fields required (zod default)
const registerSchema = z.object({
  username: z
    .string({ required_error: 'El nombre de usuario es obligatorio' })
    .min(4, 'El nombre de usuario debe tener al menos 4 caracteres')
    .max(15, 'El nombre de usuario no puede superar 15 caracteres')
    .regex(/^[a-zA-Z0-9]+$/, 'El nombre de usuario solo puede contener letras y números'),

  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),

  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .regex(/[A-Z]/, 'La contraseña debe tener al menos una letra mayúscula')
    .regex(/[0-9]/, 'La contraseña debe tener al menos un número'),
});

const resendVerificationSchema = z.object({
  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),
});

const deleteSchema = z.object({
  username: z
    .string({ required_error: 'El nombre de usuario es obligatorio' })
    .min(4, 'Usuario o contraseña incorrectos')
    .max(15, 'Usuario o contraseña incorrectos')
    .regex(/^[a-zA-Z0-9]+$/, 'Usuario o contraseña incorrectos'),

  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

module.exports = { registerSchema, resendVerificationSchema, deleteSchema };
