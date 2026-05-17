import { useEffect, useMemo, useState } from 'react';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import {
  Activity,
  Fingerprint,
  KeyRound,
  Loader2,
  LogOut,
  MonitorSmartphone,
  Shield,
  Trash2,
  UserRound,
  UsersRound
} from 'lucide-react';
import {
  api,
  type AdminDashboard,
  type AdminUser,
  type AuditLog,
  type CredentialSummary,
  type Role,
  type SessionSummary,
  type User
} from './api';

type View = 'login' | 'register' | 'dashboard' | 'admin';
type AccountTab = 'overview' | 'passkeys' | 'sessions';
type AdminTab = 'dashboard' | 'users' | 'audit';
type Toast = { id: number; type: 'success' | 'error'; message: string };

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [view, setView] = useState<View>('login');
  const [accountTab, setAccountTab] = useState<AccountTab>('overview');
  const [adminTab, setAdminTab] = useState<AdminTab>('dashboard');
  const [username, setUsername] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [dashboard, setDashboard] = useState<AdminDashboard | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [myCredentials, setMyCredentials] = useState<CredentialSummary[]>([]);
  const [mySessions, setMySessions] = useState<SessionSummary[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState('');
  const [adminCredentials, setAdminCredentials] = useState<Record<string, CredentialSummary[]>>({});
  const [adminSessions, setAdminSessions] = useState<Record<string, SessionSummary[]>>({});

  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    setLoading(true);
    api
      .me()
      .then(({ user: currentUser }) => {
        setUser(currentUser);
        setView(currentUser ? 'dashboard' : 'login');
      })
      .catch((error: Error) => notify('error', error.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!user || view !== 'dashboard') return;

    if (accountTab === 'passkeys') void loadMyCredentials();
    if (accountTab === 'sessions') void loadMySessions();
  }, [user, view, accountTab]);

  useEffect(() => {
    if (!isAdmin || view !== 'admin') return;

    if (adminTab === 'dashboard') void loadAdminDashboard();
    if (adminTab === 'users') void loadUsers();
    if (adminTab === 'audit') void loadAuditLogs();
  }, [isAdmin, view, adminTab]);

  const title = useMemo(() => {
    if (view === 'register') return 'Register phone passkey';
    if (view === 'admin') return 'Admin';
    if (user) return 'Account';
    return 'Fingerprint sign in';
  }, [user, view]);

  function notify(type: Toast['type'], message: string) {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, type, message }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 4200);
  }

  async function run(action: () => Promise<void>, success?: string) {
    setBusy(true);

    try {
      await action();
      if (success) notify('success', success);
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Something went wrong');
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    await run(async () => {
      const options = await api.registrationOptions(username);
      const registration = await startRegistration({ optionsJSON: options });
      await api.verifyRegistration(username, registration);
      setUser(null);
      setView('login');
      setUsername('');
    }, 'Passkey registered. Sign in with the same username.');
  }

  async function login() {
    await run(async () => {
      const options = await api.loginOptions(username);
      const authentication = await startAuthentication({ optionsJSON: options });
      const result = await api.verifyLogin(username, authentication);
      setUser(result.user);
      setView('dashboard');
      setAccountTab('overview');
      setUsername('');
    }, 'Signed in.');
  }

  async function logout() {
    await run(async () => {
      await api.logout();
      setUser(null);
      setView('login');
      setAdminUsers([]);
      setDashboard(null);
      setAuditLogs([]);
      setMyCredentials([]);
      setMySessions([]);
      setAdminCredentials({});
      setAdminSessions({});
    }, 'Signed out.');
  }

  async function loadMyCredentials() {
    setLoading(true);
    try {
      const result = await api.myCredentials();
      setMyCredentials(result.credentials);
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Could not load passkeys');
    } finally {
      setLoading(false);
    }
  }

  async function addPasskey() {
    await run(async () => {
      const options = await api.myCredentialOptions();
      const registration = await startRegistration({ optionsJSON: options });
      await api.verifyMyCredential(registration, `Phone passkey ${myCredentials.length + 1}`);
      await loadMyCredentials();
    }, 'Passkey added.');
  }

  async function renamePasskey(id: string, currentName: string | null) {
    const name = window.prompt('Passkey name', currentName ?? 'Phone passkey');
    if (name === null) return;

    await run(async () => {
      await api.renameMyCredential(id, name);
      await loadMyCredentials();
    }, 'Passkey renamed.');
  }

  async function deletePasskey(id: string) {
    if (!window.confirm('Delete this passkey?')) return;

    await run(async () => {
      await api.deleteMyCredential(id);
      await loadMyCredentials();
    }, 'Passkey deleted.');
  }

  async function loadMySessions() {
    setLoading(true);
    try {
      const result = await api.mySessions();
      setCurrentSessionId(result.currentSessionId);
      setMySessions(result.sessions);
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Could not load sessions');
    } finally {
      setLoading(false);
    }
  }

  async function revokeMySession(id: string) {
    await run(async () => {
      await api.revokeMySession(id);
      if (id === currentSessionId) {
        setUser(null);
        setView('login');
        notify('error', 'Session revoked. Please sign in again.');
        return;
      }
      await loadMySessions();
    }, 'Session revoked.');
  }

  async function loadAdminDashboard() {
    setLoading(true);
    try {
      setDashboard(await api.adminDashboard());
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Could not load dashboard');
    } finally {
      setLoading(false);
    }
  }

  async function loadUsers() {
    setLoading(true);
    try {
      const result = await api.users();
      setAdminUsers(result.users);
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Could not load users');
    } finally {
      setLoading(false);
    }
  }

  async function loadAuditLogs() {
    setLoading(true);
    try {
      const result = await api.auditLogs();
      setAuditLogs(result.auditLogs);
    } catch (error) {
      notify('error', error instanceof Error ? error.message : 'Could not load audit logs');
    } finally {
      setLoading(false);
    }
  }

  async function updateUser(id: string, body: Partial<Pick<User, 'username' | 'role' | 'disabled'>>) {
    await run(async () => {
      await api.updateUser(id, body);
      await loadUsers();
      if (adminTab === 'dashboard') await loadAdminDashboard();
    }, 'User updated.');
  }

  async function renameUser(user: AdminUser) {
    const nextUsername = window.prompt('New username', user.username);
    if (nextUsername === null || nextUsername === user.username) return;
    await updateUser(user.id, { username: nextUsername });
  }

  async function showAdminCredentials(id: string) {
    await run(async () => {
      const result = await api.credentials(id);
      setAdminCredentials((current) => ({ ...current, [id]: result.credentials }));
    });
  }

  async function showAdminSessions(id: string) {
    await run(async () => {
      const result = await api.userSessions(id);
      setAdminSessions((current) => ({ ...current, [id]: result.sessions }));
    });
  }

  async function revokeAdminSession(userId: string, sessionId: string) {
    await run(async () => {
      await api.revokeUserSession(userId, sessionId);
      await showAdminSessions(userId);
      if (adminTab === 'dashboard') await loadAdminDashboard();
    }, 'Session revoked.');
  }

  return (
    <main className="shell">
      <ToastStack toasts={toasts} />
      <nav className="topbar">
        <button className="brand" onClick={() => setView(user ? 'dashboard' : 'login')}>
          <Fingerprint size={22} />
          <span>Z-Auth</span>
        </button>
        <div className="navActions">
          {user && (
            <>
              <button className={view === 'dashboard' ? 'active' : ''} onClick={() => setView('dashboard')}>
                <UserRound size={18} />
                Account
              </button>
              {isAdmin && (
                <button className={view === 'admin' ? 'active' : ''} onClick={() => setView('admin')}>
                  <UsersRound size={18} />
                  Admin
                </button>
              )}
              <button onClick={logout} disabled={busy}>
                <LogOut size={18} />
                Sign out
              </button>
            </>
          )}
        </div>
      </nav>

      <section className="panel">
        <div className="heading">
          <div>
            <p className="eyebrow">WebAuthn required</p>
            <h1>{title}</h1>
          </div>
          <div className="statusBadge">
            <Shield size={18} />
            User verification required
          </div>
        </div>

        {loading && <Loader label="Loading" />}

        {!user && (view === 'login' || view === 'register') && (
          <AuthForm
            mode={view}
            username={username}
            setUsername={setUsername}
            busy={busy}
            onLogin={login}
            onRegister={register}
            switchMode={() => setView(view === 'login' ? 'register' : 'login')}
          />
        )}

        {user && view === 'dashboard' && (
          <AccountPanel
            user={user}
            tab={accountTab}
            setTab={setAccountTab}
            credentials={myCredentials}
            sessions={mySessions}
            currentSessionId={currentSessionId}
            busy={busy}
            onAddPasskey={addPasskey}
            onRenamePasskey={renamePasskey}
            onDeletePasskey={deletePasskey}
            onRevokeSession={revokeMySession}
          />
        )}

        {user && view === 'admin' && isAdmin && (
          <AdminPanel
            tab={adminTab}
            setTab={setAdminTab}
            dashboard={dashboard}
            users={adminUsers}
            auditLogs={auditLogs}
            credentials={adminCredentials}
            sessions={adminSessions}
            busy={busy}
            onUpdate={updateUser}
            onRename={renameUser}
            onCredentials={showAdminCredentials}
            onSessions={showAdminSessions}
            onRevokeSession={revokeAdminSession}
          />
        )}
      </section>
    </main>
  );
}

function AuthForm(props: {
  mode: 'login' | 'register';
  username: string;
  setUsername: (value: string) => void;
  busy: boolean;
  onLogin: () => void;
  onRegister: () => void;
  switchMode: () => void;
}) {
  const isLogin = props.mode === 'login';

  return (
    <form
      className="authForm"
      onSubmit={(event) => {
        event.preventDefault();
        void (isLogin ? props.onLogin() : props.onRegister());
      }}
    >
      <label>
        Username
        <input
          autoComplete="username webauthn"
          minLength={3}
          maxLength={32}
          pattern="[a-z0-9_-]+"
          placeholder="your_name"
          value={props.username}
          onChange={(event) => props.setUsername(event.target.value)}
          required
        />
      </label>
      <button className="primary" disabled={props.busy}>
        {props.busy ? <Loader2 className="spin" size={20} /> : <Fingerprint size={20} />}
        {props.busy ? 'Waiting for verifier' : isLogin ? 'Sign in' : 'Register'}
      </button>
      <button className="linkButton" type="button" onClick={props.switchMode}>
        {isLogin ? 'Register a phone passkey' : 'Use an existing passkey'}
      </button>
    </form>
  );
}

function AccountPanel(props: {
  user: User;
  tab: AccountTab;
  setTab: (tab: AccountTab) => void;
  credentials: CredentialSummary[];
  sessions: SessionSummary[];
  currentSessionId: string;
  busy: boolean;
  onAddPasskey: () => void;
  onRenamePasskey: (id: string, currentName: string | null) => void;
  onDeletePasskey: (id: string) => void;
  onRevokeSession: (id: string) => void;
}) {
  return (
    <div className="stack">
      <div className="tabs">
        <button className={props.tab === 'overview' ? 'active' : ''} onClick={() => props.setTab('overview')}>Overview</button>
        <button className={props.tab === 'passkeys' ? 'active' : ''} onClick={() => props.setTab('passkeys')}>Passkeys</button>
        <button className={props.tab === 'sessions' ? 'active' : ''} onClick={() => props.setTab('sessions')}>Sessions</button>
      </div>

      {props.tab === 'overview' && (
        <div className="dashboard">
          <Metric label="Username" value={props.user.username} />
          <Metric label="Role" value={props.user.role} />
          <Metric label="Status" value={props.user.disabled ? 'Disabled' : 'Active'} />
        </div>
      )}

      {props.tab === 'passkeys' && (
        <section className="stack">
          <div className="sectionHeader">
            <h2>Passkeys</h2>
            <button className="primary" onClick={props.onAddPasskey} disabled={props.busy}>
              <KeyRound size={18} />
              Add phone
            </button>
          </div>
          {props.credentials.length === 0 ? (
            <EmptyState text="No passkeys found." />
          ) : (
            <div className="list">
              {props.credentials.map((credential) => (
                <div className="listItem" key={credential.id}>
                  <div>
                    <strong>{credential.name ?? 'Phone passkey'}</strong>
                    <p>{credential.deviceType ?? 'Unknown device'} · {credential.backedUp ? 'Backed up' : 'Device bound'}</p>
                    <p>Last used {formatDate(credential.lastUsedAt)} · {credential.transports.join(', ') || 'No transport metadata'}</p>
                  </div>
                  <div className="rowActions">
                    <button onClick={() => props.onRenamePasskey(credential.id, credential.name)} disabled={props.busy}>Rename</button>
                    <button onClick={() => props.onDeletePasskey(credential.id)} disabled={props.busy}>
                      <Trash2 size={16} />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {props.tab === 'sessions' && (
        <SessionList
          sessions={props.sessions}
          currentSessionId={props.currentSessionId}
          busy={props.busy}
          onRevoke={props.onRevokeSession}
        />
      )}
    </div>
  );
}

function AdminPanel(props: {
  tab: AdminTab;
  setTab: (tab: AdminTab) => void;
  dashboard: AdminDashboard | null;
  users: AdminUser[];
  auditLogs: AuditLog[];
  credentials: Record<string, CredentialSummary[]>;
  sessions: Record<string, SessionSummary[]>;
  busy: boolean;
  onUpdate: (id: string, body: Partial<Pick<User, 'username' | 'role' | 'disabled'>>) => void;
  onRename: (user: AdminUser) => void;
  onCredentials: (id: string) => void;
  onSessions: (id: string) => void;
  onRevokeSession: (userId: string, sessionId: string) => void;
}) {
  return (
    <div className="stack">
      <div className="tabs">
        <button className={props.tab === 'dashboard' ? 'active' : ''} onClick={() => props.setTab('dashboard')}>Dashboard</button>
        <button className={props.tab === 'users' ? 'active' : ''} onClick={() => props.setTab('users')}>Users</button>
        <button className={props.tab === 'audit' ? 'active' : ''} onClick={() => props.setTab('audit')}>Audit</button>
      </div>

      {props.tab === 'dashboard' && (
        <section className="stack">
          <div className="dashboard">
            <Metric label="Users" value={props.dashboard?.metrics.totalUsers ?? 0} />
            <Metric label="Disabled" value={props.dashboard?.metrics.disabledUsers ?? 0} />
            <Metric label="Active sessions" value={props.dashboard?.metrics.activeSessions ?? 0} />
            <Metric label="Passkeys" value={props.dashboard?.metrics.totalPasskeys ?? 0} />
            <Metric label="7d logins" value={props.dashboard?.metrics.recentLogins ?? 0} />
            <Metric label="7d failed" value={props.dashboard?.metrics.failedLogins ?? 0} />
          </div>
          <AuditTable auditLogs={props.dashboard?.auditLogs ?? []} />
        </section>
      )}

      {props.tab === 'users' && (
        <div className="tableWrap">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th>Passkeys</th>
                <th>Sessions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {props.users.map((user) => (
                <tr key={user.id}>
                  <td>{user.username}</td>
                  <td>
                    <select
                      value={user.role}
                      disabled={props.busy}
                      onChange={(event) => props.onUpdate(user.id, { role: event.target.value as Role })}
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>{user.disabled ? 'Disabled' : 'Active'}</td>
                  <td>{user.credentialCount}</td>
                  <td>{user.sessionCount}</td>
                  <td className="rowActions">
                    <button onClick={() => props.onRename(user)} disabled={props.busy}>Rename</button>
                    <button onClick={() => props.onUpdate(user.id, { disabled: !user.disabled })} disabled={props.busy}>
                      {user.disabled ? 'Enable' : 'Disable'}
                    </button>
                    <button onClick={() => props.onCredentials(user.id)} disabled={props.busy}>Passkeys</button>
                    <button onClick={() => props.onSessions(user.id)} disabled={props.busy}>Sessions</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {props.users.length === 0 && <EmptyState text="No users found." />}

          {props.users.map((user) => (
            <UserDetails
              key={`${user.id}-details`}
              user={user}
              credentials={props.credentials[user.id]}
              sessions={props.sessions[user.id]}
              busy={props.busy}
              onRevokeSession={props.onRevokeSession}
            />
          ))}
        </div>
      )}

      {props.tab === 'audit' && <AuditTable auditLogs={props.auditLogs} />}
    </div>
  );
}

function UserDetails(props: {
  user: AdminUser;
  credentials?: CredentialSummary[];
  sessions?: SessionSummary[];
  busy: boolean;
  onRevokeSession: (userId: string, sessionId: string) => void;
}) {
  if (!props.credentials && !props.sessions) return null;

  return (
    <div className="detailGrid">
      {props.credentials && (
        <section className="detailPanel">
          <h2>{props.user.username} passkeys</h2>
          {props.credentials.length === 0 ? (
            <EmptyState text="No passkeys found." />
          ) : (
            props.credentials.map((credential) => (
              <div className="compactItem" key={credential.id}>
                <strong>{credential.name ?? 'Phone passkey'}</strong>
                <span>{credential.deviceType ?? 'Unknown'} · Last used {formatDate(credential.lastUsedAt)}</span>
              </div>
            ))
          )}
        </section>
      )}
      {props.sessions && (
        <section className="detailPanel">
          <h2>{props.user.username} sessions</h2>
          <SessionList
            sessions={props.sessions}
            busy={props.busy}
            onRevoke={(sessionId) => props.onRevokeSession(props.user.id, sessionId)}
          />
        </section>
      )}
    </div>
  );
}

function SessionList(props: {
  sessions: SessionSummary[];
  currentSessionId?: string;
  busy: boolean;
  onRevoke: (id: string) => void;
}) {
  if (props.sessions.length === 0) {
    return <EmptyState text="No sessions found." />;
  }

  return (
    <div className="list">
      {props.sessions.map((session) => (
        <div className="listItem" key={session.id}>
          <div>
            <strong>
              {session.id === props.currentSessionId ? 'Current session' : 'Session'} · {session.active ? 'Active' : 'Inactive'}
            </strong>
            <p>{session.ipAddress ?? 'Unknown IP'} · {session.userAgent ?? 'Unknown browser'}</p>
            <p>Created {formatDate(session.createdAt)} · Expires {formatDate(session.expiresAt)}</p>
          </div>
          <button onClick={() => props.onRevoke(session.id)} disabled={props.busy || !session.active}>
            Revoke
          </button>
        </div>
      ))}
    </div>
  );
}

function AuditTable({ auditLogs }: { auditLogs: AuditLog[] }) {
  if (auditLogs.length === 0) {
    return <EmptyState text="No audit events found." />;
  }

  return (
    <div className="tableWrap">
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Actor</th>
            <th>Target</th>
            <th>Time</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {auditLogs.map((log) => (
            <tr key={log.id}>
              <td>{log.action}</td>
              <td>{log.actorUsername ?? 'system'}</td>
              <td>{log.targetUsername ?? '-'}</td>
              <td>{formatDate(log.createdAt)}</td>
              <td>{log.ipAddress ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Loader({ label }: { label: string }) {
  return (
    <div className="loader">
      <Loader2 className="spin" size={18} />
      {label}
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty">{text}</p>;
}

function ToastStack({ toasts }: { toasts: Toast[] }) {
  return (
    <div className="toastStack">
      {toasts.map((toast) => (
        <div className={`toast ${toast.type}`} key={toast.id}>
          {toast.message}
        </div>
      ))}
    </div>
  );
}

function formatDate(value: string | null | undefined) {
  if (!value) return 'never';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(value));
}
