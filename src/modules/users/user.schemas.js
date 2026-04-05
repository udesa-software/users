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

  acceptedTerms: z
    .boolean({ required_error: 'Leer y aceptar los Términos y Condiciones y la Política de Privacidad es obligatorio' }),

});

const resendVerificationSchema = z.object({
  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),
});

// CA.3: solo pide contraseña como confirmación — el usuario se identifica por JWT
const deleteSchema = z.object({
  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

// H6: editar perfil — al menos un campo obligatorio, email no editable (CA.2)
const updateProfileSchema = z
  .object({
    username: z
      .string()
      .min(4, 'El nombre de usuario debe tener al menos 4 caracteres')
      .max(15, 'El nombre de usuario no puede superar 15 caracteres')
      .regex(/^[a-zA-Z0-9]+$/, 'El nombre de usuario solo puede contener letras y números')
      .trim()
      .optional(),

    biography: z
      .string()
      .max(150, 'La biografía no puede superar los 150 caracteres') // CA.1
      .optional(),
  })
  .refine(
    (data) => data.username !== undefined || data.biography !== undefined,
    { message: 'Debés enviar al menos un campo para actualizar (username o biography)' }
  );

module.exports = { registerSchema, resendVerificationSchema, deleteSchema, updateProfileSchema };
