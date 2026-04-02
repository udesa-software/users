const { z } = require('zod');

const createAdminSchema = z.object({
  email: z
    .string({ required_error: 'El email es obligatorio' })
    .email('El formato del email no es válido'),

  role: z.enum(['superadmin', 'moderator'], {
    required_error: 'El rol es obligatorio',
    invalid_type_error: "El rol debe ser 'superadmin' o 'moderator'",
  }),
});

module.exports = { createAdminSchema };
