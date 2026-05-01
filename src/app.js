const express = require('express');
const cookieParser = require('cookie-parser');
const userRouter = require('./modules/users/user.routes');
const authRouter = require('./modules/auth/auth.routes');
const internalRouter = require('./modules/users/internal.routes');
const { errorHandler } = require('./middlewares/errorHandler');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
  console.log(`[UsersService] ${req.method} ${req.url}`);
  next();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/users', userRouter);
app.use('/api/auth', authRouter);
// Rutas internas — solo accesibles desde la red Docker con x-internal-secret
app.use('/internal', internalRouter);

// 404 handler
app.use((req, res, next) => {
  console.log(`[UsersService] 404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json({ error: 'Ruta no encontrada en el servicio de usuarios' });
});

// Global error handler — must be last
app.use(errorHandler);

module.exports = app;
