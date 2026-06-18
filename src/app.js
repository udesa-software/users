const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const userRouter = require('./modules/users/user.routes');
const authRouter = require('./modules/auth/auth.routes');
const internalRouter = require('./modules/users/internal.routes');
const { errorHandler } = require('./middlewares/errorHandler');
const { httpLogger } = require('./observability/httpMiddleware');

const app = express();

app.use(express.json({ limit: '10mb' })); // 10mb para aceptar imágenes en base64 (~5MB imagen = ~6.7MB base64)
app.use(cookieParser());

const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));
app.use(httpLogger);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/users', userRouter);
app.use('/api/auth', authRouter);
// Rutas internas — solo accesibles desde la red Docker con x-internal-secret
app.use('/internal', internalRouter);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada en el servicio de usuarios' });
});

// Global error handler — must be last
app.use(errorHandler);

module.exports = app;
