# Users Service

Microservicio de usuarios y autenticación para UdeSA-Migos. Maneja registro, verificación de email, login, logout, recuperación de contraseña y eliminación de cuenta.

## Stack

- **Runtime**: Node.js (CommonJS)
- **Framework**: Express
- **Base de datos**: PostgreSQL 16
- **ORM**: Ninguno — queries SQL directas con `pg`
- **Autenticación**: JWT (`jsonwebtoken`)
- **Hash de contraseñas**: `bcryptjs`
- **Validación**: Zod
- **Emails**: Nodemailer (con fallback a consola en desarrollo)
- **Infraestructura**: Docker + Docker Compose

---

## Requisitos

- [Docker](https://www.docker.com/) y Docker Compose
- Node.js 18+ (solo si corrés sin Docker)

---

## Variables de entorno

Creá un archivo `.env` en la raíz del proyecto (o en `src/` si usás esa ubicación):

```env
PORT=3000

DB_HOST=db
DB_PORT=5432
DB_NAME=users_db
DB_USER=admin
DB_PASSWORD=secret

# SMTP opcional — si no se configura, los emails se imprimen en consola
SMTP_HOST=sandbox.smtp.mailtrap.io
SMTP_PORT=587
SMTP_USER=<tu_usuario_mailtrap>
SMTP_PASS=<tu_password_mailtrap>
SMTP_FROM=noreply@udesamigos.com

APP_URL=http://localhost:3000

JWT_SECRET=una_clave_secreta_larga_y_aleatoria
JWT_EXPIRES_IN=7d
```

> Si `SMTP_HOST`, `SMTP_USER` o `SMTP_PASS` están vacíos, el servicio imprime los links de verificación/reset en los logs en lugar de enviar emails reales.

---

## Cómo correr

### Con Docker (recomendado)

```bash
# Primera vez o si cambiaron las migraciones
docker-compose up --build

# Desde la segunda vez
docker-compose up

# Si la DB quedó en un estado inconsistente (borrar todo y recrear)
docker-compose down -v
docker-compose up --build
```

La API queda disponible en `http://localhost:3000`.
La DB queda expuesta en `localhost:5433` (para conectarse con un cliente como DBeaver o TablePlus).

### Sin Docker (desarrollo local)

```bash
npm install
# Requiere una instancia de PostgreSQL corriendo localmente
npm run dev   # nodemon — recarga automática al guardar
# o
npm start     # sin recarga automática
```

---

## Estructura del proyecto

```
src/
├── server.js              # Punto de entrada: migraciones + arranque del servidor
├── app.js                 # Configuración de Express: middlewares globales y rutas
├── config/
│   ├── env.js             # Validación de variables de entorno con Zod
│   ├── database.js        # Pool de conexiones a PostgreSQL
│   └── mailer.js          # Configuración de Nodemailer + funciones de envío
├── middlewares/
│   ├── authenticate.js    # Verifica JWT + token_version en DB
│   ├── validate.js        # Valida req.body contra un schema Zod
│   └── errorHandler.js    # AppError + handler global de errores
├── modules/
│   ├── users/
│   │   ├── user.routes.js
│   │   ├── user.schemas.js
│   │   ├── user.controller.js
│   │   ├── user.service.js
│   │   └── user.repository.js
│   └── auth/
│       ├── auth.routes.js
│       ├── auth.schemas.js
│       ├── auth.controller.js
│       ├── auth.service.js
│       └── (usa user.repository.js)
└── db/
    └── migrations/
        └── 001_create_users.sql
```

---

## Endpoints

### Users — `/api/users`

#### `POST /api/users/register`
Registra un nuevo usuario. Envía email de verificación.

**Body:**
```json
{
  "username": "juanperez",
  "email": "juan@example.com",
  "password": "Password1",
  "acceptedTerms": true
}
```

**Reglas:**
- `username`: 4–15 caracteres, solo letras y números, único
- `email`: formato válido, único (case-insensitive)
- `password`: mínimo 8 caracteres, al menos 1 mayúscula y 1 número
- `acceptedTerms`: debe ser `true`

**Respuesta exitosa `201`:**
```json
{
  "message": "Registro exitoso. Revisá tu email para verificar tu cuenta.",
  "user": { "id": "...", "username": "juanperez", "email": "juan@example.com", "is_verified": false, "created_at": "..." }
}
```

---

#### `GET /api/users/verify-email?token=<uuid>`
Verifica el email del usuario usando el token recibido por email.

**Query param:** `token` — UUID enviado por email (expira en 24 horas)

**Respuesta exitosa `200`:**
```json
{ "message": "Cuenta verificada exitosamente. Ya podés iniciar sesión." }
```

---

#### `POST /api/auth/resend-verification`
Reenvía el email de verificación con un nuevo token (24 horas).

**Body:**
```json
{ "email": "juan@example.com" }
```

**Respuesta exitosa `200`:**
```json
{ "message": "Email de verificación reenviado." }
```

---

#### `POST /api/users/delete`
Elimina la cuenta (soft-delete). Requiere JWT y confirmación de contraseña.

**Headers:** `Authorization: Bearer <token>`

**Body:**
```json
{ "password": "Password1" }
```

**Respuesta exitosa `200`:**
```json
{ "message": "Tu cuenta ha sido eliminada." }
```

---

### Auth — `/api/auth`

#### `POST /api/auth/login`
Inicia sesión. Devuelve JWT con expiración de 7 días.

**Body:**
```json
{
  "identifier": "juan@example.com",
  "password": "Password1"
}
```

> `identifier` puede ser email o username.

**Respuesta exitosa `200`:**
```json
{
  "message": "Inicio de sesión exitoso.",
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "user": { "id": "...", "username": "juanperez", "email": "juan@example.com", ... }
}
```

**Errores posibles:**
| Código | Causa |
|--------|-------|
| `401` | Credenciales inválidas |
| `403` | Cuenta no verificada o suspendida |
| `423` | Cuenta bloqueada temporalmente (5 intentos fallidos → 15 min) |

---

#### `POST /api/auth/logout`
Revoca el JWT activo incrementando `token_version` en la DB. Todos los tokens emitidos anteriormente quedan inválidos.

**Headers:** `Authorization: Bearer <token>`

**Respuesta exitosa `200`:**
```json
{ "message": "Sesión cerrada exitosamente." }
```

---

#### `POST /api/auth/forgot-password`
Solicita un link de reset de contraseña por email (expira en 10 minutos). Tiene throttling de 1 solicitud por minuto por cuenta.

**Body:**
```json
{ "identifier": "juan@example.com" }
```

> Siempre responde el mismo mensaje genérico para no revelar si el usuario existe.

**Respuesta `200`:**
```json
{ "message": "Si el correo o usuario está registrado, recibirás un link para restablecer tu contraseña." }
```

---

#### `GET /api/auth/reset-password?token=<uuid>`
Verifica que el token de reset sea válido y no esté expirado.

**Respuesta exitosa `200`:**
```json
{ "message": "Token válido. Por favor, ingresá tu nueva contraseña.", "token": "..." }
```

---

#### `POST /api/auth/reset-password`
Cambia la contraseña usando el token de reset. Invalida todos los JWT activos.

**Body:**
```json
{
  "token": "uuid-del-email",
  "password": "NuevaPassword1",
  "confirmPassword": "NuevaPassword1"
}
```

**Respuesta exitosa `200`:**
```json
{ "message": "Tu contraseña ha sido actualizada con éxito. Por favor, iniciá sesión de nuevo." }
```

---

## Seguridad implementada

| Mecanismo | Descripción |
|-----------|-------------|
| Hash de contraseñas | `bcryptjs` con 12 rounds |
| JWT con expiración | Tokens firmados con `HS256`, expiran en 7 días |
| Revocación de JWT | Campo `token_version` en DB — logout e invalidación al cambiar contraseña |
| Bloqueo por intentos fallidos | 5 intentos incorrectos → bloqueo 15 minutos |
| Soft-delete | Las cuentas eliminadas no se borran de la DB (`deleted_at`) |
| Validación de input | Zod en todos los endpoints — rechaza requests malformados antes del controller |
| SQL injection | Queries parametrizadas con `$1`, `$2` — nunca concatenación de strings |
| Emails case-insensitive | `LOWER()` en queries e índices únicos |
| Token de verificación | UUID con expiración de 24 horas |
| Token de reset | UUID con expiración de 10 minutos + throttling de 1 por minuto |

---

## Esquema de la base de datos

```sql
users (
  id                        UUID PRIMARY KEY,
  username                  VARCHAR(15) NOT NULL UNIQUE,
  email                     VARCHAR(255) NOT NULL,        -- índice único sobre LOWER(email)
  password_hash             VARCHAR(255) NOT NULL,
  is_verified               BOOLEAN DEFAULT FALSE,
  verify_token              UUID,
  token_expires_at          TIMESTAMPTZ,
  accepted_terms            BOOLEAN DEFAULT FALSE,
  accepted_terms_at         TIMESTAMPTZ,
  failed_login_attempts     INT DEFAULT 0,
  locked_until              TIMESTAMPTZ,
  is_suspended              BOOLEAN DEFAULT FALSE,
  deleted_at                TIMESTAMPTZ,
  password_reset_token      UUID,
  password_reset_expires_at TIMESTAMPTZ,
  last_reset_request_at     TIMESTAMPTZ,
  token_version             INT DEFAULT 1,
  created_at                TIMESTAMPTZ DEFAULT NOW(),
  updated_at                TIMESTAMPTZ DEFAULT NOW()
)
```

---

## Cómo probar con Postman

1. Levantá el servidor: `docker-compose up --build`
2. Registrá un usuario: `POST /api/users/register`
3. Copiá el token de verificación de los logs de Docker
4. Verificá el email: `GET /api/users/verify-email?token=<token>`
5. Hacé login: `POST /api/auth/login` → copiá el JWT
6. Para endpoints protegidos, agregá el header: `Authorization: Bearer <jwt>`
