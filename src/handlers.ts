import { AuthDB } from './db.js';
import { Email } from './email.js';
import { AuthError } from './error.js';
import { AuthProvider } from './providers/types.js';
import { RETURN_TO_COOKIE } from './returnTo.js';
import { Session, SessionManager } from './session.js';
import * as z from 'zod';

export function createHandlers({
  providers,
  db,
  defaultReturnTo = '/',
  email: emailService,
  sessions,
  getPublicSession = (session) => session,
}: {
  providers: Record<string, AuthProvider>;
  db: AuthDB;
  defaultReturnTo?: string;
  email?: Email;
  sessions: SessionManager;
  getPublicSession?: (session: Session) => Record<string, any>;
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

  function handleOAuthLoginRequest(req: Request, opts: { provider: string }) {
    const url = new URL(req.url);
    const providerName = opts.provider;
    if (!(providerName in providers)) {
      throw new Error(`Unknown provider: ${providerName}`);
    }
    const provider = providers[providerName as keyof typeof providers];
    const loginUrl = provider.getLoginUrl();

    return new Response(null, {
      status: 302,
      headers: {
        location: loginUrl,
        'set-cookie': `${RETURN_TO_COOKIE}=${
          url.searchParams.get('returnTo') ?? defaultReturnTo
        }; Path=/`,
      },
    });
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
    const sessionHeaders = await sessions.updateSession(session);
    return new Response(null, {
      status: 302,
      headers: {
        ...sessionHeaders,
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
  }

  async function handleLogoutRequest(req: Request) {
    const url = new URL(req.url);
    const returnTo = url.searchParams.get('returnTo') ?? defaultReturnTo;
    return new Response(null, {
      status: 302,
      headers: {
        ...sessions.clearSession(),
        location: returnTo,
      },
    });
  }

  async function handleSendEmailVerificationRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const name = formData.get('name');
    const returnTo = formData.get('returnTo');

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
    });

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json',
      },
    });
  }

  async function handleVerifyEmailRequest(req: Request) {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    const email = url.searchParams.get('email');
    const password = url.searchParams.get('password');
    if (!code || !email) {
      throw new Error('Missing code or email');
    }
    if (!password) {
      throw new Error('Missing password');
    }
    const dbCode = await db.getVerificationCode?.(email, code);
    if (!dbCode) {
      throw new Error('Invalid code');
    }
    if (dbCode.expiresAt < Date.now()) {
      throw new Error('Code expired');
    }
    const user = await db.getUserByEmail(email);
    if (user) {
      throw new AuthError('User already exists', 409);
    }
    const { id: userId } = await db.insertUser({
      fullName: dbCode.name,
      friendlyName: null,
      email,
      imageUrl: null,
      plaintextPassword: password,
      emailVerifiedAt: new Date().toISOString(),
    });
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
    return new Response(null, {
      status: 302,
      headers: {
        ...(await sessions.updateSession(session)),
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
  }

  async function handleEmailLoginRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const password = formData.get('password');
    const returnTo = formData.get('returnTo');

    const params = z
      .object({
        email: z.string().email(),
        password: z.string().min(1),
        returnTo: z.string().url().optional(),
      })
      .parse({ email, password, returnTo });

    const user = await db.getUserByEmailAndPassword?.(
      params.email,
      params.password,
    );
    if (!user) {
      throw new Error('Invalid email or password');
    }
    const session = await sessions.createSession(user.id);
    return new Response(null, {
      status: 302,
      headers: {
        ...(await sessions.updateSession(session)),
        location: params.returnTo ?? defaultReturnTo,
      },
    });
  }

  async function handleResetPasswordRequest(req: Request) {
    const formData = await req.formData();

    const email = formData.get('email');
    const returnTo = formData.get('returnTo');

    const params = z
      .object({
        email: z.string().email(),
        returnTo: z.string().url().optional(),
      })
      .parse({ email, returnTo });

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
      returnTo: params.returnTo || defaultReturnTo,
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
    return new Response(null, {
      status: 302,
      headers: {
        ...(await sessions.updateSession(session)),
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
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
    const sessionHeaders = await sessions.updateSession(session);
    return new Response(
      JSON.stringify({ session: getPublicSession(session) }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json',
          ...sessionHeaders,
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
  };
}
