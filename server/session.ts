import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { Role, type User } from '@prisma/client';
import { prisma } from './db';
import { config } from './config';

const cookieName = 'authx_session';
const maxAgeMs = 1000 * 60 * 60 * 24 * 7;

export type PublicUser = Pick<User, 'id' | 'username' | 'role' | 'disabled' | 'createdAt'>;

declare global {
  namespace Express {
    interface Request {
      user?: PublicUser;
      sessionId?: string;
    }
  }
}

function sign(value: string) {
  return crypto.createHmac('sha256', config.sessionSecret).update(value).digest('base64url');
}

function encodeSessionCookie(sessionId: string) {
  return `${sessionId}.${sign(sessionId)}`;
}

function decodeSessionCookie(cookie?: string) {
  if (!cookie) {
    return null;
  }

  const [sessionId, signature] = cookie.split('.');

  if (!sessionId || !signature || signature !== sign(sessionId)) {
    return null;
  }

  return sessionId;
}

export function setSessionCookie(response: Response, sessionId: string) {
  response.cookie(cookieName, encodeSessionCookie(sessionId), {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.isProduction,
    maxAge: maxAgeMs,
    path: '/'
  });
}

export function clearSessionCookie(response: Response) {
  response.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.isProduction,
    path: '/'
  });
}

export function getRequestMetadata(request: Request) {
  return {
    ipAddress: request.ip || request.socket.remoteAddress || null,
    userAgent: request.get('user-agent') || null
  };
}

export async function createSession(response: Response, userId: string, metadata?: { ipAddress?: string | null; userAgent?: string | null }) {
  const session = await prisma.session.create({
    data: {
      id: crypto.randomBytes(32).toString('base64url'),
      userId,
      ipAddress: metadata?.ipAddress ?? null,
      userAgent: metadata?.userAgent ?? null,
      expiresAt: new Date(Date.now() + maxAgeMs)
    }
  });

  setSessionCookie(response, session.id);
}

export async function attachUser(request: Request, response: Response, next: NextFunction) {
  const sessionId = decodeSessionCookie(request.cookies?.[cookieName]);

  if (!sessionId) {
    return next();
  }

  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { user: true }
  });

  if (!session || session.expiresAt <= new Date() || session.revokedAt || session.user.disabled) {
    await prisma.session.deleteMany({ where: { id: sessionId } });
    clearSessionCookie(response);
    return next();
  }

  request.sessionId = session.id;
  request.user = {
    id: session.user.id,
    username: session.user.username,
    role: session.user.role,
    disabled: session.user.disabled,
    createdAt: session.user.createdAt
  };

  return next();
}

export function requireAuth(request: Request, response: Response, next: NextFunction) {
  if (!request.user) {
    return response.status(401).json({ error: 'Authentication required' });
  }

  return next();
}

export function requireAdmin(request: Request, response: Response, next: NextFunction) {
  if (!request.user) {
    return response.status(401).json({ error: 'Authentication required' });
  }

  if (request.user.role !== Role.admin) {
    return response.status(403).json({ error: 'Admin access required' });
  }

  return next();
}
