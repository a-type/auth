import { AuthDB } from './db.js';
import { Email } from './email.js';
import { AuthError } from './error.js';
import { AuthProvider } from './providers/types.js';
import {
  RETURN_TO_COOKIE,
  getAppState,
  getReturnTo,
  setAppState,
  setReturnTo,
} from './appState.js';
import { Session, SessionManager } from './session.js';
import * as z from 'zod';

export function createHandlers({
  providers,
  db,
  defaultReturnToPath: defaultReturnTo = '/',
  returnToOrigin,
  email: emailService,
  sessions,
  getPublicSession = (session) => session,
  addProvidersToExistingUsers = true,
}: {
  providers: Record<string, AuthProvider>;
  db: AuthDB;
  /**
   * A default path to land on after login if none
   * was specified in the original request.
   */
  defaultReturnToPath?: string;
  /**
   * Which origin your login process returns the user to.
   * In a 'real' auth system this would be a list of allowed origins
   * which could be controlled by the app. But since this is just for
   * me and my apps don't need that, I just set it manually. It's easier!
   */
  returnToOrigin: string;
  email?: Email;
  sessions: SessionManager;
  getPublicSession?: (session: Session) => Record<string, any>;
  /**
   * When a user logs in or signs up with the same email from a different provider,
   * but already has an account, should we add the new provider to the existing account?
   * If false, we'll throw an error.
   */
  addProvidersToExistingUsers?: boolean;
}) {
  const supportsEmail =
    !!db.insertVerificationCode &&
    !!db.getUserByEmailAndPassword &&
    !!db.getVerificationCode &&
    !!db.consumeVerificationCode;
  if (emailService && !supportsEmail) {
    throw new Error(
      'Implement optional db fields "insertVerificationCode", "getUserByEmailAndPassword", "getVerificationCode", and "consumeVerificationCode" to support email',
    );
  }

  function resolveReturnTo(path: string) {
    return new URL(path, returnToOrigin).toString();
  }

  /**
   * Redirects the response back to wherever the user meant to return to.
   * Reads from the returnTo cookie, or a query param on the request URL.
   * Also appends appState if available, and session data.
   */
  function toRedirect(
    req: Request,
    session: {
      headers: Record<string, string>;
      searchParams?: URLSearchParams;
    },
    overrides: {
      returnTo?: string;
      appState?: string;
    } = {},
  ) {
    // get returnTo
    const returnTo = resolveReturnTo(
      overrides.returnTo ?? getReturnTo(req) ?? defaultReturnTo,
    );
    // add search params to destination for appState and session
    const url = new URL(returnTo);
    if (session.searchParams) {
      for (const [key, value] of session.searchParams) {
        url.searchParams.append(key, value);
      }
    }
    const appState = overrides.appState ?? getAppState(req);
    if (appState) {
      url.searchParams.append('appState', appState);
    }

    return new Response(null, {
      status: 302,
      headers: {
        location: url.toString(),
        ...session.headers,
      },
    });
  }

  function handleOAuthLoginRequest(req: Request, opts: { provider: string }) {
    const url = new URL(req.url);
    const providerName = opts.provider;
    if (!(providerName in providers)) {
      throw new Error(`Unknown provider: ${providerName}`);
    }
    const provider = providers[providerName as keyof typeof providers];
    const loginUrl = provider.getLoginUrl();

    const res = new Response(null, {
      status: 302,
      headers: {
        location: loginUrl,
      },
    });

    setReturnTo(res, url.searchParams.get('returnTo') ?? defaultReturnTo);
    setAppState(res, url.searchParams.get('appState'));

    return res;
  }

  async function handleOAuthCallbackRequest(
    req: Request,
    opts: { provider: string },
  ) {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    if (!code) {
      throw new Error('Missing code');
    }

    const providerName = opts.provider;
    if (!(providerName in providers)) {
      throw new Error(`Unknown provider: ${providerName}`);
    }

    const provider = providers[providerName as keyof typeof providers];

    const tokens = await provider.getTokens(code);
    const profile = await provider.getProfile(tokens.accessToken);

    const account = await db.getAccountByProviderAccountId(
      providerName,
      profile.id,
    );

    let userId: string;
    if (account) {
      userId = account.userId;
    } else {
      const user = await db.getUserByEmail(profile.email);
      if (user) {
        if (!addProvidersToExistingUsers) {
          throw new AuthError('User already exists', 409);
        }
        userId = user.id;
      } else {
        const user = await db.insertUser({
          fullName: profile.fullName,
          friendlyName: profile.friendlyName ?? null,
          email: profile.email,
          emailVerifiedAt: null,
          imageUrl: profile.avatarUrl ?? null,
          plaintextPassword: null,
        });
        userId = user.id;
      }
      await db.insertAccount({
        userId,
        type: 'oauth',
        provider: providerName,
        providerAccountId: profile.id,
        refreshToken: tokens.refreshToken,
        accessToken: tokens.accessToken,
        expiresAt: tokens.expiresAt,
        tokenType: tokens.tokenType,
        scope: tokens.scope,
        idToken: tokens.idToken ?? null,
      });
    }

    const session = await sessions.createSession(userId);
    const sessionUpdate = await sessions.updateSession(session, {
      sendRefreshToken: true,
    });

    return toRedirect(req, sessionUpdate);
  }

  async function handleLogoutRequest(req: Request) {
    const session = sessions.clearSession();
    return toRedirect(req, session);
  }

  async function handleSendEmailVerificationRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const name = formData.get('name');
    const returnToRaw = formData.get('returnTo') ?? '';
    if (!email || !name) {
      throw new Error('Missing email or name');
    }
    if (typeof email !== 'string') {
      throw new Error('Invalid email');
    }
    if (typeof name !== 'string') {
      throw new Error('Invalid name');
    }
    if (typeof returnToRaw !== 'string') {
      throw new Error('Invalid returnTo');
    }

    const returnTo = resolveReturnTo(returnToRaw);
    const appState = formData.get('appState') as string | undefined;

    const params = z
      .object({
        email: z.string().email(),
        name: z.string().min(1),
        returnTo: z.string().url().optional(),
      })
      .parse({ email, name, returnTo });

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 36);
    const code = Math.floor(Math.random() * 100000).toString();
    await db.insertVerificationCode?.({
      email: params.email,
      code,
      expiresAt: expiresAt.getTime(),
      name: params.name,
    });
    await emailService?.sendEmailVerification({
      to: params.email,
      code,
      returnTo: params.returnTo || defaultReturnTo,
      appState,
    });

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json',
      },
    });
  }

  async function handleVerifyEmailRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const password = formData.get('password');
    const code = formData.get('code');

    if (!code || !email) {
      throw new Error('Missing code or email');
    }
    if (!password) {
      throw new Error('Missing password');
    }
    if (typeof email !== 'string') {
      throw new Error('Invalid email');
    }
    if (typeof code !== 'string') {
      throw new Error('Invalid code');
    }
    if (typeof password !== 'string') {
      throw new Error('Invalid password');
    }

    const dbCode = await db.getVerificationCode?.(email, code);
    if (!dbCode) {
      throw new Error('Invalid code');
    }
    if (dbCode.expiresAt < Date.now()) {
      throw new Error('Code expired');
    }
    const user = await db.getUserByEmail(email);
    let userId: string;
    if (user) {
      if (!addProvidersToExistingUsers) {
        throw new AuthError('User already exists', 409);
      } else {
        userId = user.id;
      }
    } else {
      const user = await db.insertUser({
        fullName: dbCode.name,
        friendlyName: null,
        email,
        imageUrl: null,
        plaintextPassword: password,
        emailVerifiedAt: new Date().toISOString(),
      });
      userId = user.id;
    }
    await db.insertAccount({
      userId,
      type: 'email',
      provider: 'email',
      providerAccountId: email,
      refreshToken: null,
      accessToken: null,
      expiresAt: null,
      tokenType: null,
      scope: null,
      idToken: null,
    });
    await db.consumeVerificationCode?.(email, code);
    const session = await sessions.createSession(userId);
    const sessionUpdate = await sessions.updateSession(session, {
      sendRefreshToken: true,
    });
    return toRedirect(req, sessionUpdate);
  }

  async function handleEmailLoginRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const password = formData.get('password');
    const returnTo = formData.get('returnTo');
    const appState = formData.get('appState');

    const params = z
      .object({
        email: z.string().email(),
        password: z.string().min(1),
        returnTo: z.string().url().optional(),
        appState: z.string().optional(),
      })
      .parse({ email, password, returnTo, appState });

    const user = await db.getUserByEmailAndPassword?.(
      params.email,
      params.password,
    );
    if (!user) {
      throw new Error('Invalid email or password');
    }
    const session = await sessions.createSession(user.id);
    const sessionUpdate = await sessions.updateSession(session, {
      sendRefreshToken: true,
    });
    return toRedirect(req, sessionUpdate, {
      returnTo: params.returnTo,
      appState: params.appState,
    });
  }

  async function handleResetPasswordRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const returnTo = formData.get('returnTo');
    const appState = formData.get('appState');

    const params = z
      .object({
        email: z.string().email(),
        returnTo: z.string().url().optional(),
        appState: z.string().optional(),
      })
      .parse({ email, returnTo, appState });

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 36);
    const code = Math.floor(Math.random() * 10000000).toString();
    await db.insertVerificationCode?.({
      email: params.email,
      code,
      expiresAt: expiresAt.getTime(),
      name: '',
    });
    await emailService?.sendPasswordReset({
      to: params.email,
      code,
      returnTo: resolveReturnTo(params.returnTo || defaultReturnTo),
      appState: params.appState,
    });

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json',
      },
    });
  }

  async function handleVerifyPasswordResetRequest(req: Request) {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    const email = url.searchParams.get('email');
    if (!code || !email) {
      throw new Error('Missing code or email');
    }
    const dbCode = await db.getVerificationCode?.(email, code);
    if (!dbCode) {
      throw new Error('Invalid code');
    }
    if (dbCode.expiresAt < Date.now()) {
      throw new Error('Code expired');
    }
    const user = await db.getUserByEmail(email);
    if (!user) {
      throw new Error('User not found');
    }
    const session = await sessions.createSession(user.id);
    const sessionUpdate = await sessions.updateSession(session, {
      sendRefreshToken: true,
    });
    return toRedirect(req, sessionUpdate);
  }

  async function handleSessionRequest(req: Request) {
    const session = await sessions.getSession(req);
    if (!session) {
      return new Response(JSON.stringify({ session: null }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      });
    }
    // refresh session
    return new Response(
      JSON.stringify({ session: getPublicSession(session) }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      },
    );
  }

  async function handleRefreshSessionRequest(req: Request) {
    const accessToken = sessions.getAccessToken(req);
    const refreshToken = sessions.getRefreshToken(req);

    if (!accessToken || !refreshToken) {
      throw new AuthError('Invalid session', 401);
    }

    const { headers, searchParams } = await sessions.refreshSession(
      accessToken,
      refreshToken,
    );

    return new Response(
      JSON.stringify({
        ok: true,
        refreshToken: searchParams.get('refreshToken'),
      }),
      {
        status: 200,
        headers: {
          ...headers,
          'content-type': 'application/json',
        },
      },
    );
  }

  return {
    handleOAuthLoginRequest,
    handleOAuthCallbackRequest,
    handleLogoutRequest,
    handleSendEmailVerificationRequest,
    handleVerifyEmailRequest,
    handleEmailLoginRequest,
    handleResetPasswordRequest,
    handleVerifyPasswordResetRequest,
    handleSessionRequest,
    handleRefreshSessionRequest,
  };
}
