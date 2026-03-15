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

module.exports = { sendVerificationEmail };
