import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON
} from '@simplewebauthn/server';
import type { Credential, User } from '@prisma/client';
import { config } from './config';
import { base64urlToBuffer, bufferToBase64url } from './encoding';

export async function makeRegistrationOptions(user: User, credentials: Credential[]) {
  return generateRegistrationOptions({
    rpName: config.webauthn.rpName,
    rpID: config.webauthn.rpID,
    userID: Buffer.from(user.id),
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    excludeCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: credential.transports as AuthenticatorTransportFuture[]
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required'
    }
  });
}

export async function verifyRegistration(
  response: RegistrationResponseJSON,
  expectedChallenge: string
) {
  return verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.webauthn.origin,
    expectedRPID: config.webauthn.rpID,
    requireUserVerification: true
  });
}

export async function makeAuthenticationOptions(credentials: Credential[]) {
  return generateAuthenticationOptions({
    rpID: config.webauthn.rpID,
    userVerification: 'required',
    allowCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: credential.transports as AuthenticatorTransportFuture[]
    }))
  });
}

export async function verifyAuthentication(
  response: AuthenticationResponseJSON,
  credential: Credential,
  expectedChallenge: string
) {
  return verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.webauthn.origin,
    expectedRPID: config.webauthn.rpID,
    credential: {
      id: credential.credentialId,
      publicKey: new Uint8Array(credential.publicKey),
      counter: Number(credential.counter),
      transports: credential.transports as AuthenticatorTransportFuture[]
    },
    requireUserVerification: true
  });
}

export function credentialPublicKeyToBytes(publicKey: Uint8Array) {
  return base64urlToBuffer(bufferToBase64url(publicKey));
}
