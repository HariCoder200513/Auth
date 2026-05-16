import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON
} from '@simplewebauthn/browser';

export type Role = 'user' | 'admin';

export type User = {
  id: string;
  username: string;
  role: Role;
  disabled: boolean;
  createdAt?: string;
};

export type AdminUser = User & {
  credentialCount: number;
  sessionCount: number;
};

export type CredentialSummary = {
  id: string;
  name: string | null;
  credentialId: string;
  transports: string[];
  backedUp: boolean;
  deviceType: string | null;
  counter: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  createdAt: string;
};

export type SessionSummary = {
  id: string;
  userId: string;
  userAgent: string | null;
  ipAddress: string | null;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
  active: boolean;
};

export type AuditLog = {
  id: string;
  action: string;
  actorUserId: string | null;
  actorUsername: string | null;
  targetUserId: string | null;
  targetUsername: string | null;
  metadata: unknown;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
};

export type AdminDashboard = {
  metrics: {
    totalUsers: number;
    disabledUsers: number;
    activeSessions: number;
    totalPasskeys: number;
    recentLogins: number;
    failedLogins: number;
  };
  auditLogs: AuditLog[];
};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers
    }
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error ?? 'Request failed');
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export const api = {
  me: () => request<{ user: User | null }>('/api/auth/me'),
  registrationOptions: (username: string) =>
    request<PublicKeyCredentialCreationOptionsJSON>('/api/auth/register/options', {
      method: 'POST',
      body: JSON.stringify({ username })
    }),
  verifyRegistration: (username: string, registration: RegistrationResponseJSON) =>
    request<{ registered: true }>('/api/auth/register/verify', {
      method: 'POST',
      body: JSON.stringify({ username, registration })
    }),
  loginOptions: (username: string) =>
    request<PublicKeyCredentialRequestOptionsJSON>('/api/auth/login/options', {
      method: 'POST',
      body: JSON.stringify({ username })
    }),
  verifyLogin: (username: string, authentication: AuthenticationResponseJSON) =>
    request<{ user: User }>('/api/auth/login/verify', {
      method: 'POST',
      body: JSON.stringify({ username, authentication })
    }),
  logout: () => request<void>('/api/auth/logout', { method: 'POST' }),
  myCredentials: () => request<{ credentials: CredentialSummary[] }>('/api/me/credentials'),
  myCredentialOptions: () =>
    request<PublicKeyCredentialCreationOptionsJSON>('/api/me/credentials/options', { method: 'POST' }),
  verifyMyCredential: (registration: RegistrationResponseJSON, name: string) =>
    request<{ credential: CredentialSummary }>('/api/me/credentials/verify', {
      method: 'POST',
      body: JSON.stringify({ registration, name })
    }),
  renameMyCredential: (id: string, name: string) =>
    request<{ credential: CredentialSummary }>(`/api/me/credentials/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name })
    }),
  deleteMyCredential: (id: string) => request<void>(`/api/me/credentials/${id}`, { method: 'DELETE' }),
  mySessions: () => request<{ currentSessionId: string; sessions: SessionSummary[] }>('/api/me/sessions'),
  revokeMySession: (id: string) => request<void>(`/api/me/sessions/${id}`, { method: 'DELETE' }),
  adminDashboard: () => request<AdminDashboard>('/api/admin/dashboard'),
  auditLogs: () => request<{ auditLogs: AuditLog[] }>('/api/admin/audit-logs'),
  users: () => request<{ users: AdminUser[] }>('/api/admin/users'),
  updateUser: (id: string, body: Partial<Pick<User, 'username' | 'role' | 'disabled'>>) =>
    request<{ user: User }>(`/api/admin/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body)
    }),
  credentials: (id: string) => request<{ credentials: CredentialSummary[] }>(`/api/admin/users/${id}/credentials`),
  userSessions: (id: string) => request<{ sessions: SessionSummary[] }>(`/api/admin/users/${id}/sessions`),
  revokeUserSession: (userId: string, sessionId: string) =>
    request<void>(`/api/admin/users/${userId}/sessions/${sessionId}`, { method: 'DELETE' })
};
