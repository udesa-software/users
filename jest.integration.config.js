/** @type {import('jest').Config} */
module.exports = {
  // Solo corre archivos *.integration.test.js dentro de tests/integration/
  testMatch: ['<rootDir>/tests/integration/*.integration.test.js'],

  // Carga las variables de entorno ANTES de que cualquier módulo sea requerido
  setupFiles: ['./src/tests/setupEnv.js'],

  // Tiempo extendido por round-trips a la base de datos
  testTimeout: 20000,

  // Un worker para evitar condiciones de carrera entre tests que comparten la DB
  maxWorkers: 1,

  // Fuerza la salida tras completar todos los tests.
  // Necesario porque pg y ioredis mantienen handles asíncronos abiertos.
  forceExit: true,

  // Directorio separado para no pisar la cobertura de los unit tests
  coverageDirectory: 'coverage-integration',

  // Cobertura sobre todas las capas que ejercitan los integration tests
  collectCoverageFrom: [
    'src/modules/users/user.routes.js',
    'src/modules/users/user.controller.js',
    'src/modules/users/user.service.js',
    'src/modules/users/user.repository.js',
    'src/modules/auth/auth.routes.js',
    'src/modules/auth/auth.controller.js',
    'src/modules/auth/auth.service.js',
    'src/middlewares/authenticate.js',
  ],
};
