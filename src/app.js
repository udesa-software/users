const express = require('express');
const userRouter = require('./modules/users/user.routes');
const authRouter = require('./modules/auth/auth.routes');
const adminAuthRouter = require('./modules/admin-auth/admin-auth.routes');
const adminRouter = require('./modules/admins/admin.routes');
const { errorHandler } = require('./middlewares/errorHandler');

const app = express();

app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/users', userRouter);
app.use('/api/auth', authRouter);
app.use('/api/admin/auth', adminAuthRouter);
app.use('/api/admin/admins', adminRouter);

// Global error handler — must be last
app.use(errorHandler);

module.exports = app;
