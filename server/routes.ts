import { Router, type Request } from 'express';
import { Role, type Prisma } from '@prisma/client';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON
} from '@simplewebauthn/server';
import { prisma } from './db';
import { createSession, requireAdmin, requireAuth, clearSessionCookie, getRequestMetadata } from './session';
import {
  credentialPublicKeyToBytes,
  makeAuthenticationOptions,
  makeRegistrationOptions,
  verifyAuthentication,
  verifyRegistration
} from './webauthn';

const challengeTtlMs = 1000 * 60 * 5;
const reservedUsernames = new Set(['admin', 'system', 'root', 'support', 'security', 'api']);
export const router = Router();

function normalizeUsername(value: unknown) {
  if (typeof value !== 'string') {
    return '';
  }

  return value.trim().toLowerCase();
}

function validateUsername(value: unknown, options: { allowReservedExisting?: boolean } = {}) {
  const username = normalizeUsername(value);

  if (!username || username.length < 3 || username.length > 32) {
    return { username, error: 'Username must be 3-32 characters' };
  }

  if (!/^[a-z0-9_-]+$/.test(username)) {
    return { username, error: 'Use lowercase letters, numbers, underscore, or hyphen only' };
  }

  if (!options.allowReservedExisting && reservedUsernames.has(username)) {
    return { username, error: 'This username is reserved' };
  }

  return { username };
}

function serializeUser(user: { id: string; username: string; role: Role; disabled: boolean; createdAt?: Date }) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    disabled: user.disabled,
    createdAt: user.createdAt
  };
}

function serializeCredential(credential: {
  id: string;
  name: string | null;
  credentialId: string;
  transports: string[];
  backedUp: boolean;
  deviceType: string | null;
  counter: bigint;
  lastUsedAt: Date | null;
  lastUsedIp: string | null;
  createdAt: Date;
}) {
  return {
    id: credential.id,
    name: credential.name,
    credentialId: credential.credentialId,
    transports: credential.transports,
    backedUp: credential.backedUp,
    deviceType: credential.deviceType,
    counter: credential.counter.toString(),
    lastUsedAt: credential.lastUsedAt,
    lastUsedIp: credential.lastUsedIp,
    createdAt: credential.createdAt
  };
}

function serializeSession(session: {
  id: string;
  userId: string;
  userAgent: string | null;
  ipAddress: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}) {
  return {
    id: session.id,
    userId: session.userId,
    userAgent: session.userAgent,
    ipAddress: session.ipAddress,
    expiresAt: session.expiresAt,
    revokedAt: session.revokedAt,
    createdAt: session.createdAt,
    active: !session.revokedAt && session.expiresAt > new Date()
  };
}

function serializeAuditLog(log: {
  id: string;
  action: string;
  actorUserId: string | null;
  targetUserId: string | null;
  metadata: Prisma.JsonValue | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  actor?: { username: string } | null;
  target?: { username: string } | null;
}) {
  return {
    id: log.id,
    action: log.action,
    actorUserId: log.actorUserId,
    actorUsername: log.actor?.username ?? null,
    targetUserId: log.targetUserId,
    targetUsername: log.target?.username ?? null,
    metadata: log.metadata,
    ipAddress: log.ipAddress,
    userAgent: log.userAgent,
    createdAt: log.createdAt
  };
}

async function audit(
  request: Request,
  action: string,
  data: { actorUserId?: string | null; targetUserId?: string | null; metadata?: Prisma.InputJsonValue } = {}
) {
  const metadata = getRequestMetadata(request);

  await prisma.auditLog.create({
    data: {
      action,
      actorUserId: data.actorUserId ?? request.user?.id ?? null,
      targetUserId: data.targetUserId ?? null,
      metadata: data.metadata,
      ipAddress: metadata.ipAddress,
      userAgent: metadata.userAgent
    }
  });
}

async function storeChallenge(kind: string, challenge: string, data: { userId?: string; username?: string }) {
  const selectors = [data.userId ? { userId: data.userId } : null, data.username ? { username: data.username } : null].filter(
    (selector): selector is { userId: string } | { username: string } => selector !== null
  );

  await prisma.challenge.deleteMany({
    where: {
      kind,
      OR: selectors
    }
  });

  await prisma.challenge.create({
    data: {
      kind,
      challenge,
      userId: data.userId,
      username: data.username,
      expiresAt: new Date(Date.now() + challengeTtlMs)
    }
  });
}

async function consumeChallenge(kind: string, data: { userId?: string; username?: string }) {
  const selectors = [data.userId ? { userId: data.userId } : null, data.username ? { username: data.username } : null].filter(
    (selector): selector is { userId: string } | { username: string } => selector !== null
  );

  const challenge = await prisma.challenge.findFirst({
    where: {
      kind,
      expiresAt: { gt: new Date() },
      OR: selectors
    },
    orderBy: { createdAt: 'desc' }
  });

  if (!challenge) {
    throw new Error('Challenge expired or missing');
  }

  await prisma.challenge.deleteMany({ where: { id: challenge.id } });
  return challenge.challenge;
}

router.get('/auth/me', (request, response) => {
  response.json({ user: request.user ?? null });
});

router.post('/auth/register/options', async (request, response, next) => {
  try {
    const validation = validateUsername(request.body?.username, { allowReservedExisting: true });

    if (validation.error) {
      await audit(request, 'registration_failed', { metadata: { reason: validation.error, username: validation.username } });
      return response.status(400).json({ error: validation.error });
    }

    let user = await prisma.user.findUnique({ where: { username: validation.username } });

    if (!user && reservedUsernames.has(validation.username)) {
      await audit(request, 'registration_failed', { metadata: { reason: 'reserved_username', username: validation.username } });
      return response.status(400).json({ error: 'This username is reserved' });
    }

    if (!user) {
      user = await prisma.user.create({ data: { username: validation.username } });
    }

    if (user.disabled) {
      await audit(request, 'registration_failed', { targetUserId: user.id, metadata: { reason: 'disabled' } });
      return response.status(403).json({ error: 'Account is disabled' });
    }

    const credentials = await prisma.credential.findMany({ where: { userId: user.id } });

    if (credentials.length > 0) {
      await audit(request, 'registration_failed', { targetUserId: user.id, metadata: { reason: 'account_already_registered' } });
      return response.status(409).json({ error: 'This account already has a passkey. Sign in to add another device.' });
    }

    const options = await makeRegistrationOptions(user, credentials);
    await storeChallenge('registration', options.challenge, { userId: user.id, username: validation.username });

    return response.json(options);
  } catch (error) {
    return next(error);
  }
});

router.post('/auth/register/verify', async (request, response, next) => {
  try {
    const validation = validateUsername(request.body?.username, { allowReservedExisting: true });
    const registration = request.body?.registration as RegistrationResponseJSON | undefined;

    if (validation.error || !registration) {
      await audit(request, 'registration_failed', { metadata: { reason: validation.error ?? 'missing_response', username: validation.username } });
      return response.status(400).json({ error: validation.error ?? 'Username and registration response are required' });
    }

    const user = await prisma.user.findUnique({ where: { username: validation.username } });

    if (!user || user.disabled) {
      await audit(request, 'registration_failed', { targetUserId: user?.id, metadata: { reason: 'account_unavailable', username: validation.username } });
      return response.status(403).json({ error: 'Account is unavailable' });
    }

    const expectedChallenge = await consumeChallenge('registration', { userId: user.id, username: validation.username });
    const verification = await verifyRegistration(registration, expectedChallenge);

    if (!verification.verified || !verification.registrationInfo) {
      await audit(request, 'registration_failed', { targetUserId: user.id, metadata: { reason: 'verification_failed' } });
      return response.status(400).json({ error: 'Passkey registration failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    const created = await prisma.credential.create({
      data: {
        userId: user.id,
        name: 'Phone passkey',
        credentialId: credential.id,
        publicKey: credentialPublicKeyToBytes(credential.publicKey),
        counter: BigInt(credential.counter),
        transports: registration.response.transports ?? [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp
      }
    });

    await audit(request, 'registration_succeeded', {
      targetUserId: user.id,
      metadata: { credentialId: created.id, username: user.username }
    });

    return response.json({ registered: true });
  } catch (error) {
    return next(error);
  }
});

router.post('/auth/login/options', async (request, response, next) => {
  try {
    const validation = validateUsername(request.body?.username, { allowReservedExisting: true });

    if (validation.error) {
      await audit(request, 'login_failed', { metadata: { reason: validation.error, username: validation.username } });
      return response.status(400).json({ error: validation.error });
    }

    const user = await prisma.user.findUnique({
      where: { username: validation.username },
      include: { credentials: true }
    });

    if (!user || user.disabled || user.credentials.length === 0) {
      await audit(request, 'login_failed', { targetUserId: user?.id, metadata: { reason: 'no_available_passkey', username: validation.username } });
      return response.status(404).json({ error: 'No passkey is registered for this user' });
    }

    const options = await makeAuthenticationOptions(user.credentials);
    await storeChallenge('authentication', options.challenge, { userId: user.id, username: validation.username });

    return response.json(options);
  } catch (error) {
    return next(error);
  }
});

router.post('/auth/login/verify', async (request, response, next) => {
  try {
    const validation = validateUsername(request.body?.username, { allowReservedExisting: true });
    const authentication = request.body?.authentication as AuthenticationResponseJSON | undefined;

    if (validation.error || !authentication) {
      await audit(request, 'login_failed', { metadata: { reason: validation.error ?? 'missing_response', username: validation.username } });
      return response.status(400).json({ error: validation.error ?? 'Username and authentication response are required' });
    }

    const user = await prisma.user.findUnique({
      where: { username: validation.username },
      include: { credentials: true }
    });

    if (!user || user.disabled) {
      await audit(request, 'login_failed', { targetUserId: user?.id, metadata: { reason: 'account_unavailable', username: validation.username } });
      return response.status(403).json({ error: 'Account is unavailable' });
    }

    const credential = user.credentials.find((item) => item.credentialId === authentication.id);

    if (!credential) {
      await audit(request, 'login_failed', { targetUserId: user.id, metadata: { reason: 'credential_mismatch' } });
      return response.status(400).json({ error: 'Credential is not registered to this account' });
    }

    const expectedChallenge = await consumeChallenge('authentication', { userId: user.id, username: validation.username });
    const verification = await verifyAuthentication(authentication, credential, expectedChallenge);

    if (!verification.verified) {
      await audit(request, 'login_failed', { targetUserId: user.id, metadata: { reason: 'verification_failed' } });
      return response.status(400).json({ error: 'Passkey authentication failed' });
    }

    const metadata = getRequestMetadata(request);

    await prisma.credential.update({
      where: { id: credential.id },
      data: {
        counter: BigInt(verification.authenticationInfo.newCounter),
        lastUsedAt: new Date(),
        lastUsedIp: metadata.ipAddress
      }
    });

    await createSession(response, user.id, metadata);
    await audit(request, 'login_succeeded', { actorUserId: user.id, targetUserId: user.id, metadata: { credentialId: credential.id } });
    return response.json({ user: serializeUser(user) });
  } catch (error) {
    return next(error);
  }
});

router.post('/auth/logout', requireAuth, async (request, response, next) => {
  try {
    if (request.sessionId) {
      await prisma.session.updateMany({ where: { id: request.sessionId }, data: { revokedAt: new Date() } });
    }

    await audit(request, 'logout', { targetUserId: request.user?.id ?? null, metadata: { sessionId: request.sessionId } });
    clearSessionCookie(response);
    return response.status(204).send();
  } catch (error) {
    return next(error);
  }
});

router.get('/me/credentials', requireAuth, async (request, response, next) => {
  try {
    const credentials = await prisma.credential.findMany({
      where: { userId: request.user!.id },
      orderBy: { createdAt: 'desc' }
    });

    return response.json({ credentials: credentials.map(serializeCredential) });
  } catch (error) {
    return next(error);
  }
});

router.post('/me/credentials/options', requireAuth, async (request, response, next) => {
  try {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: request.user!.id } });
    const credentials = await prisma.credential.findMany({ where: { userId: user.id } });
    const options = await makeRegistrationOptions(user, credentials);
    await storeChallenge('credential_registration', options.challenge, { userId: user.id, username: user.username });

    return response.json(options);
  } catch (error) {
    return next(error);
  }
});

router.post('/me/credentials/verify', requireAuth, async (request, response, next) => {
  try {
    const registration = request.body?.registration as RegistrationResponseJSON | undefined;
    const name = typeof request.body?.name === 'string' && request.body.name.trim() ? request.body.name.trim().slice(0, 60) : 'Phone passkey';

    if (!registration) {
      return response.status(400).json({ error: 'Registration response is required' });
    }

    const user = await prisma.user.findUniqueOrThrow({ where: { id: request.user!.id } });
    const expectedChallenge = await consumeChallenge('credential_registration', { userId: user.id, username: user.username });
    const verification = await verifyRegistration(registration, expectedChallenge);

    if (!verification.verified || !verification.registrationInfo) {
      await audit(request, 'passkey_add_failed', { targetUserId: user.id, metadata: { reason: 'verification_failed' } });
      return response.status(400).json({ error: 'Passkey registration failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    const created = await prisma.credential.create({
      data: {
        userId: user.id,
        name,
        credentialId: credential.id,
        publicKey: credentialPublicKeyToBytes(credential.publicKey),
        counter: BigInt(credential.counter),
        transports: registration.response.transports ?? [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp
      }
    });

    await audit(request, 'passkey_added', { targetUserId: user.id, metadata: { credentialId: created.id, name } });
    return response.json({ credential: serializeCredential(created) });
  } catch (error) {
    return next(error);
  }
});

router.patch('/me/credentials/:id', requireAuth, async (request, response, next) => {
  try {
    const credentialId = String(request.params.id);
    const name = typeof request.body?.name === 'string' ? request.body.name.trim().slice(0, 60) : '';

    if (!name) {
      return response.status(400).json({ error: 'Passkey name is required' });
    }

    const credential = await prisma.credential.update({
      where: { id: credentialId, userId: request.user!.id },
      data: { name }
    });

    await audit(request, 'passkey_renamed', { targetUserId: request.user!.id, metadata: { credentialId, name } });
    return response.json({ credential: serializeCredential(credential) });
  } catch (error) {
    return next(error);
  }
});

router.delete('/me/credentials/:id', requireAuth, async (request, response, next) => {
  try {
    const credentialId = String(request.params.id);
    const count = await prisma.credential.count({ where: { userId: request.user!.id } });

    if (count <= 1) {
      return response.status(400).json({ error: 'You cannot delete your last passkey' });
    }

    await prisma.credential.delete({ where: { id: credentialId, userId: request.user!.id } });
    await audit(request, 'passkey_deleted', { targetUserId: request.user!.id, metadata: { credentialId } });
    return response.status(204).send();
  } catch (error) {
    return next(error);
  }
});

router.get('/me/sessions', requireAuth, async (request, response, next) => {
  try {
    const sessions = await prisma.session.findMany({
      where: { userId: request.user!.id },
      orderBy: { createdAt: 'desc' }
    });

    return response.json({ currentSessionId: request.sessionId, sessions: sessions.map(serializeSession) });
  } catch (error) {
    return next(error);
  }
});

router.delete('/me/sessions/:id', requireAuth, async (request, response, next) => {
  try {
    const sessionId = String(request.params.id);
    await prisma.session.updateMany({
      where: { id: sessionId, userId: request.user!.id },
      data: { revokedAt: new Date() }
    });

    await audit(request, 'session_revoked', { targetUserId: request.user!.id, metadata: { sessionId, self: true } });

    if (sessionId === request.sessionId) {
      clearSessionCookie(response);
    }

    return response.status(204).send();
  } catch (error) {
    return next(error);
  }
});

router.get('/admin/dashboard', requireAdmin, async (_request, response, next) => {
  try {
    const since = new Date(Date.now() - 1000 * 60 * 60 * 24 * 7);
    const [totalUsers, disabledUsers, activeSessions, totalPasskeys, recentLogins, failedLogins, auditLogs] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { disabled: true } }),
      prisma.session.count({ where: { revokedAt: null, expiresAt: { gt: new Date() } } }),
      prisma.credential.count(),
      prisma.auditLog.count({ where: { action: 'login_succeeded', createdAt: { gte: since } } }),
      prisma.auditLog.count({ where: { action: 'login_failed', createdAt: { gte: since } } }),
      prisma.auditLog.findMany({
        orderBy: { createdAt: 'desc' },
        take: 10,
        include: { actor: { select: { username: true } }, target: { select: { username: true } } }
      })
    ]);

    return response.json({
      metrics: { totalUsers, disabledUsers, activeSessions, totalPasskeys, recentLogins, failedLogins },
      auditLogs: auditLogs.map(serializeAuditLog)
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/admin/audit-logs', requireAdmin, async (_request, response, next) => {
  try {
    const auditLogs = await prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      take: 100,
      include: { actor: { select: { username: true } }, target: { select: { username: true } } }
    });

    return response.json({ auditLogs: auditLogs.map(serializeAuditLog) });
  } catch (error) {
    return next(error);
  }
});

router.get('/admin/users', requireAdmin, async (_request, response, next) => {
  try {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        _count: { select: { credentials: true, sessions: true } }
      }
    });

    return response.json({
      users: users.map((user) => ({
        ...serializeUser(user),
        credentialCount: user._count.credentials,
        sessionCount: user._count.sessions
      }))
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/admin/users/:id', requireAdmin, async (request, response, next) => {
  try {
    const userId = String(request.params.id);
    const role = request.body?.role;
    const disabled = request.body?.disabled;
    const usernameValue = request.body?.username;
    const data: { role?: Role; disabled?: boolean; username?: string } = {};
    const existing = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

    if (role !== undefined) {
      if (![Role.user, Role.admin].includes(role)) {
        return response.status(400).json({ error: 'Invalid role' });
      }

      data.role = role;
    }

    if (disabled !== undefined) {
      data.disabled = Boolean(disabled);
    }

    if (usernameValue !== undefined) {
      const validation = validateUsername(usernameValue, { allowReservedExisting: existing.username === normalizeUsername(usernameValue) });

      if (validation.error) {
        return response.status(400).json({ error: validation.error });
      }

      data.username = validation.username;
    }

    const user = await prisma.user.update({
      where: { id: userId },
      data
    });

    if (data.disabled) {
      await prisma.session.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } });
    }

    await audit(request, 'user_updated', {
      targetUserId: user.id,
      metadata: {
        previous: { username: existing.username, role: existing.role, disabled: existing.disabled },
        next: { username: user.username, role: user.role, disabled: user.disabled }
      }
    });

    return response.json({ user: serializeUser(user) });
  } catch (error) {
    return next(error);
  }
});

router.get('/admin/users/:id/credentials', requireAdmin, async (request, response, next) => {
  try {
    const userId = String(request.params.id);
    const credentials = await prisma.credential.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });

    return response.json({ credentials: credentials.map(serializeCredential) });
  } catch (error) {
    return next(error);
  }
});

router.get('/admin/users/:id/sessions', requireAdmin, async (request, response, next) => {
  try {
    const userId = String(request.params.id);
    const sessions = await prisma.session.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });

    return response.json({ sessions: sessions.map(serializeSession) });
  } catch (error) {
    return next(error);
  }
});

router.delete('/admin/users/:userId/sessions/:sessionId', requireAdmin, async (request, response, next) => {
  try {
    const userId = String(request.params.userId);
    const sessionId = String(request.params.sessionId);

    await prisma.session.updateMany({
      where: { id: sessionId, userId },
      data: { revokedAt: new Date() }
    });

    await audit(request, 'session_revoked', { targetUserId: userId, metadata: { sessionId, admin: true } });
    return response.status(204).send();
  } catch (error) {
    return next(error);
  }
});
