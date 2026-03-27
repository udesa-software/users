const nodemailer = require('nodemailer');
const { env } = require('./env');

const hasSmtp = !!(env.SMTP_HOST && env.SMTP_USER && env.SMTP_PASS);

const transporter = hasSmtp
  ? nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: parseInt(env.SMTP_PORT, 10),
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
      },
    })
  : null;

async function sendVerificationEmail(toEmail, token) {
  const verificationUrl = `${env.APP_URL}/api/users/verify-email?token=${token}`;

  if (!transporter) {
    console.log('─────────────────────────────────────────────');
    console.log('[DEV] Verification email (not sent)');
    console.log(`   To:    ${toEmail}`);
    console.log(`   URL:   ${verificationUrl}`);
    console.log('─────────────────────────────────────────────');
    return;
  }

  await transporter.sendMail({
    from: env.SMTP_FROM,
    to: toEmail,
    subject: 'Verifica tu cuenta en UdeSA-Migos',
    html: `
      <h2>Bienvenido a UdeSA-Migos!</h2>
      <p>Para activar tu cuenta, hacé click en el siguiente enlace:</p>
      <a href="${verificationUrl}" style="
        display: inline-block;
        padding: 12px 24px;
        background-color: #4F46E5;
        color: white;
        text-decoration: none;
        border-radius: 6px;
      ">Verificar cuenta</a>
      <p>Este enlace expira en <strong>24 horas</strong>.</p>
      <p>Si no creaste esta cuenta, podés ignorar este email.</p>
    `,
  });
}

async function sendResetPasswordEmail(toEmail, token) {
  const resetUrl = `${env.APP_URL}/api/auth/reset-password?token=${token}`;

  if (!transporter) {
    console.log('─────────────────────────────────────────────');
    console.log('[DEV] Reset password email (not sent)');
    console.log(`   To:    ${toEmail}`);
    console.log(`   URL:   ${resetUrl}`);
    console.log('─────────────────────────────────────────────');
    return;
  }

  await transporter.sendMail({
    from: env.SMTP_FROM,
    to: toEmail,
    subject: 'Restablece tu contraseña en UdeSA-Migos',
    html: `
      <h2>Restablecimiento de contraseña</h2>
      <p>Recibimos una solicitud para restablecer tu contraseña. Si no fuiste vos, podés ignorar este email.</p>
      <p>Hacé click en el siguiente enlace para elegir una nueva clave:</p>
      <a href="${resetUrl}" style="
        display: inline-block;
        padding: 12px 24px;
        background-color: #4F46E5;
        color: white;
        text-decoration: none;
        border-radius: 6px;
      ">Restablecer contraseña</a>
      <p>Este enlace expira en <strong>10 minutos</strong>.</p>
    `,
  });
}

async function sendPasswordChangedEmail(toEmail) {
  if (!transporter) {
    console.log('─────────────────────────────────────────────');
    console.log('[DEV] Password changed email (not sent)');
    console.log(`   To:    ${toEmail}`);
    console.log('─────────────────────────────────────────────');
    return;
  }

  await transporter.sendMail({
    from: env.SMTP_FROM,
    to: toEmail,
    subject: 'Tu contraseña ha sido modificada',
    html: `
      <h2>Notificación de cambio de contraseña</h2>
      <p>Te informamos que tu contraseña ha sido modificada con éxito.</p>
      <p>Si no realizaste este cambio, te recomendamos contactar a soporte técnico de inmediato.</p>
    `,
  });
}

module.exports = { sendVerificationEmail, sendResetPasswordEmail, sendPasswordChangedEmail };
