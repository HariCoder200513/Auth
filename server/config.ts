import 'dotenv/config';

function required(name: string, fallback?: string) {
  const value = process.env[name] ?? fallback;

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

export const config = {
  port: Number(process.env.API_PORT ?? 4000),
  sessionSecret: required('SESSION_SECRET', 'dev-only-change-me'),
  webauthn: {
    rpName: required('WEBAUTHN_RP_NAME', 'Z-Auth'),
    rpID: required('WEBAUTHN_RP_ID', 'localhost'),
    origin: required('WEBAUTHN_ORIGIN', 'http://localhost:5173').replace(/\/+$/, '')
  },
  clientOrigin: required('WEBAUTHN_ORIGIN', 'http://localhost:5173').replace(/\/+$/, ''),
  isProduction: process.env.NODE_ENV === 'production'
};
