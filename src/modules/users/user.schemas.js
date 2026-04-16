const { z } = require('zod');

const SEARCH_RADIUS_MIN = 1;
const SEARCH_RADIUS_MAX = 50;
const ALLOWED_UPDATE_FREQUENCIES = [5, 15, 30];

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


// CA.3: solo pide contraseña como confirmación — el usuario se identifica por JWT
const deleteSchema = z.object({
  password: z
    .string({ required_error: 'La contraseña es obligatoria' })
    .min(1, 'La contraseña es obligatoria'),
});

// CA.1: radio 1-50 km, CA.4: frecuencia solo 5, 15 o 30
const updatePreferencesSchema = z.object({
  search_radius_km: z
    .number({ invalid_type_error: 'El radio debe ser un número' })
    .min(SEARCH_RADIUS_MIN, `El radio de búsqueda no puede ser menor a ${SEARCH_RADIUS_MIN} km`)
    .max(SEARCH_RADIUS_MAX, `El radio de búsqueda no puede superar los ${SEARCH_RADIUS_MAX} km`)
    .optional(),
  location_update_frequency: z
    .number({ invalid_type_error: 'La frecuencia debe ser un número' })
    .refine((val) => ALLOWED_UPDATE_FREQUENCIES.includes(val), {
      message: `La frecuencia de actualización solo puede ser ${ALLOWED_UPDATE_FREQUENCIES.join(', ')} minutos`,
    })
    .optional(),
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

module.exports = {
  registerSchema,
  deleteSchema,
  updatePreferencesSchema,
  updateProfileSchema,
};
