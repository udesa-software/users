const express = require('express');
const userRouter = require('./modules/users/user.routes');
const authRouter = require('./modules/auth/auth.routes');
const { errorHandler } = require('./middlewares/errorHandler');

const app = express();

app.use(express.json());
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/users', userRouter);
app.use('/api/auth', authRouter);

// Global error handler — must be last
app.use(errorHandler);

module.exports = app;
