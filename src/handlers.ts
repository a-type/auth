import { AuthDB } from './db.js';
import { Email } from './email.js';
import { AuthProvider } from './providers/types.js';
import { RETURN_TO_COOKIE } from './returnTo.js';
import { getOrCreateSession } from './session.js';
import * as z from 'zod';

export function createHandlers({
  providers,
  db,
  defaultReturnTo = '/',
  email: emailService,
}: {
  providers: Record<string, AuthProvider>;
  db: AuthDB;
  defaultReturnTo?: string;
  email?: Email;
}) {
  const supportsEmail =
    !!db.insertVerificationCode &&
    !!db.getUserByEmailAndPassword &&
    !!db.getVerificationCode;
  if (emailService && !supportsEmail) {
    throw new Error('Implement optional db fields to support email');
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

    const res = new Response(null, {
      status: 302,
      headers: {
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
    const session = await getOrCreateSession(req, res);
    session.userId = userId;
    await session.save();
    return res;
  }

  async function handleLogoutRequest(req: Request) {
    const url = new URL(req.url);
    const returnTo = url.searchParams.get('returnTo') ?? defaultReturnTo;
    const res = new Response(null, {
      status: 302,
      headers: {
        location: returnTo,
      },
    });
    const session = await getOrCreateSession(req, res);
    session.destroy();
    return res;
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
  }

  async function handleVerifyEmailRequest(req: Request) {
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
    await db.insertAccount({
      userId: user.id,
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
    await db.insertVerificationCode?.({
      email,
      code,
      expiresAt: 0,
      name: '',
    });
    const res = new Response(null, {
      status: 302,
      headers: {
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
    const session = await getOrCreateSession(req, res);
    session.userId = user.id;
    await session.save();
    return res;
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
    const res = new Response(null, {
      status: 302,
      headers: {
        location: params.returnTo ?? defaultReturnTo,
      },
    });
    const session = await getOrCreateSession(req, res);
    session.userId = user.id;
    await session.save();
    return res;
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
    const res = new Response(null, {
      status: 302,
      headers: {
        location: url.searchParams.get('returnTo') ?? defaultReturnTo,
      },
    });
    const session = await getOrCreateSession(req, res);
    session.userId = user.id;
    await session.save();
    return res;
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
  };
}
