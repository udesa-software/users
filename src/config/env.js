const { z } = require('zod');

const envSchema = z.object({
  PORT: z.string().default('3000'),

  DB_HOST: z.string(),
  DB_PORT: z.string().default('5432'),
  DB_NAME: z.string(),
  DB_USER: z.string(),
  DB_PASSWORD: z.string(),

  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.string().default('587'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().optional(),

  APP_URL: z.string().url(),

  JWT_SECRET: z.string(),
  JWT_EXPIRES_IN: z.string().default('7d'),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),

  ALLOWED_EMAIL_DOMAIN: z.string().optional(), // ej: "udesa.edu.ar"

  INITIAL_SUPERADMIN_EMAIL: z.string().email().optional(),
  INITIAL_SUPERADMIN_TEMP_PASSWORD: z.string().optional(),
  
  MOBILE_DEEP_LINK_URL: z.string().optional(),
  MOBILE_RESET_PASSWORD_URL: z.string().optional(),

  // URL del servicio de friends (H4 CA.2/CA.4: eliminar relaciones al borrar cuenta)
  FRIENDS_SERVICE_URL: z.string().url().optional(),

  // Secreto compartido para comunicación interna entre microservicios
  INTERNAL_SECRET: z.string().optional(),

  // Desactivar SSL para postgres (útil en entornos locales/Docker)
  DB_SSL: z.string().default('true'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const env = parsed.data;

module.exports = { env };
