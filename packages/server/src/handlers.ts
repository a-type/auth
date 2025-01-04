import * as z from 'zod';
import { rawAdapter, ServerAdapter } from './adapter.js';
import {
	getAppState,
	getReturnTo,
	setAppState,
	setReturnTo,
} from './appState.js';
import { AuthDB, authDbSupportsEmail } from './db.js';
import { Email } from './email.js';
import { AuthError } from './error.js';
import { AuthProvider } from './providers/types.js';
import { Session, SessionManager } from './session.js';

export function createHandlers<Context = Request>({
	providers,
	getStorage,
	getRedirectConfig,
	email: emailService,
	sessions,
	getPublicSession = (session) => session,
	addProvidersToExistingUsers = true,
	adapter = rawAdapter as ServerAdapter<Context>,
}: {
	/**
	 * Adapters are used to extract the raw request object from the context object
	 * passed to each handler. This lets you connect handlers to different server
	 * frameworks. By default, handlers assume you are passing the raw HTTP Request
	 * object.
	 */
	adapter?: ServerAdapter<Context>;
	providers: Record<string, AuthProvider<Context>>;
	/**
	 * Gets the database interface used to store user and account data.
	 * This is passed the same context value which you pass to the handler.
	 */
	getStorage: (ctx: Context) => AuthDB | Promise<AuthDB>;

	defaultReturnToPath?: string;
	getRedirectConfig: (ctx: Context) => {
		/**
		 * Which origin your login process returns the user to.
		 * In a 'real' auth system this would be a list of allowed origins
		 * which could be controlled by the app. But since this is just for
		 * me and my apps don't need that, I just set it manually. It's easier!
		 */
		defaultReturnToOrigin: string;
		/**
		 * A default path to land on after login if none
		 * was specified in the original request.
		 */
		defaultReturnToPath?: string;
	};
	/**
	 * The Email service to use for sending verification emails.
	 */
	email?: Email<Context>;
	/**
	 * Instantiate a SessionManager with configuration for your application and
	 * pass it to this option. The Context type configured for the SessionManager
	 * must match the Context type you pass to the handlers.
	 */
	sessions: SessionManager<Context>;
	/**
	 * Allows adapting what Session data is provided to the user when they
	 * request their own session info.
	 */
	getPublicSession?: (session: Session, ctx: Context) => Record<string, any>;
	/**
	 * When a user logs in or signs up with the same email from a different provider,
	 * but already has an account, should we add the new provider to the existing account?
	 * If false, we'll throw an error.
	 */
	addProvidersToExistingUsers?: boolean;
}) {
	function validateEmailConfig(db: AuthDB) {
		if (emailService && !authDbSupportsEmail(db)) {
			throw new Error(
				'Implement optional db fields "insertVerificationCode", "getUserByEmailAndPassword", "getVerificationCode", and "consumeVerificationCode" to support email',
			);
		}
	}

	/**
	 * Does not allow app-specified return to origins, only the default.
	 * TODO: allow app-specified origins
	 */
	function resolveReturnTo(path: string | undefined, ctx: Context) {
		// full URLs not allowed
		if (path !== undefined && URL.canParse(path)) {
			throw new AuthError(
				'Invalid returnTo. Full URLs are not supported, only paths',
				400,
			);
		}
		const { defaultReturnToOrigin, defaultReturnToPath } =
			getRedirectConfig(ctx);
		return new URL(
			path ?? defaultReturnToPath ?? '/',
			defaultReturnToOrigin,
		).toString();
	}

	/**
	 * Redirects the response back to wherever the user meant to return to.
	 * Reads from the returnTo cookie, or a query param on the request URL.
	 * Also appends appState if available, and session data.
	 */
	function toRedirect(
		ctx: Context,
		session: {
			headers: Headers;
			searchParams?: URLSearchParams;
		},
		options: {
			returnTo?: string;
			appState?: string;
			message?: string;
		} = {},
	) {
		const req = adapter.getRawRequest(ctx);
		// get returnTo
		const returnTo = resolveReturnTo(options.returnTo ?? getReturnTo(req), ctx);
		// add search params to destination for appState and session
		const url = new URL(returnTo);
		if (session.searchParams) {
			for (const [key, value] of session.searchParams) {
				url.searchParams.append(key, value);
			}
		}
		if (options.message) {
			url.searchParams.append('message', options.message);
		}
		const appState = options.appState ?? getAppState(req);
		if (appState) {
			url.searchParams.append('appState', appState);
		}

		session.headers.set('location', url.toString());

		return new Response(null, {
			status: 302,
			headers: session.headers,
		});
	}

	function handleOAuthLoginRequest(ctx: Context, opts: { provider: string }) {
		const req = adapter.getRawRequest(ctx);
		const url = new URL(req.url);
		const providerName = opts.provider;
		if (!(providerName in providers)) {
			throw new Error(`Unknown provider: ${providerName}`);
		}
		const provider = providers[providerName as keyof typeof providers];
		const loginUrl = provider.getLoginUrl(ctx);

		const res = new Response(null, {
			status: 302,
			headers: {
				location: loginUrl,
			},
		});

		const sameSite = sessions.getIsSameSite(ctx);
		setReturnTo(
			res,
			url.searchParams.get('returnTo') ??
				getRedirectConfig(ctx).defaultReturnToPath ??
				'/',
			sameSite,
		);
		setAppState(res, url.searchParams.get('appState'), sameSite);

		return res;
	}

	async function handleOAuthCallbackRequest(
		ctx: Context,
		opts: { provider: string },
	) {
		const req = adapter.getRawRequest(ctx);
		const url = new URL(req.url);
		const code = url.searchParams.get('code');
		if (!code) {
			throw new AuthError(AuthError.Messages.MissingCode, 400);
		}

		const providerName = opts.provider;
		if (!(providerName in providers)) {
			throw new Error(`Unknown provider: ${providerName}`);
		}

		const provider = providers[providerName as keyof typeof providers];

		const tokens = await provider.getTokens(code, ctx);
		const profile = await provider.getProfile(tokens.accessToken, ctx);

		const db = await getStorage(ctx);

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
					throw new AuthError(AuthError.Messages.UserAlreadyExists, 409);
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

		const session = await sessions.createSession(userId, ctx);
		const sessionUpdate = await sessions.updateSession(session, ctx);

		return toRedirect(ctx, sessionUpdate);
	}

	async function handleLogoutRequest(ctx: Context) {
		const session = sessions.clearSession(ctx);
		return toRedirect(ctx, session);
	}

	async function handleSendEmailVerificationRequest(ctx: Context) {
		const req = adapter.getRawRequest(ctx);
		const db = await getStorage(ctx);

		validateEmailConfig(db);

		const formData = await req.formData();

		const email = formData.get('email');
		const name = formData.get('name');
		const returnToRaw = formData.get('returnTo') ?? '';
		if (!name || typeof name !== 'string') {
			throw new AuthError(AuthError.Messages.InvalidName, 400);
		}
		if (!email || typeof email !== 'string') {
			throw new AuthError(AuthError.Messages.MissingEmail, 400);
		}
		if (typeof returnToRaw !== 'string') {
			throw new AuthError('Invalid returnTo', 400);
		}

		const returnTo = resolveReturnTo(returnToRaw, ctx);
		const appState = formData.get('appState') as string | undefined;

		const params = z
			.object({
				email: z.string().email(),
				name: z.string().min(1),
				returnTo: z.string().optional(),
			})
			.parse({ email, name, returnTo });

		const expiresAt = new Date();
		expiresAt.setHours(expiresAt.getHours() + 36);
		const code = Math.floor(Math.random() * 100000).toString();
		await db.insertVerificationCode?.({
			email: params.email,
			code,
			expiresAt,
			name: params.name,
		});
		await emailService?.sendEmailVerification(
			{
				to: params.email,
				code,
			},
			ctx,
		);

		const res = new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: {
				'content-type': 'application/json',
			},
		});

		const sameSite = sessions.getIsSameSite(ctx);
		setAppState(res, appState, sameSite);
		setReturnTo(res, returnTo, sameSite);

		return res;
	}

	async function handleVerifyEmailRequest(ctx: Context) {
		const req = adapter.getRawRequest(ctx);
		const db = await getStorage(ctx);
		validateEmailConfig(db);

		const formData = await req.formData();

		const email = formData.get('email');
		const password = formData.get('password');
		const code = formData.get('code');

		if (!code) {
			throw new AuthError(AuthError.Messages.MissingCode, 400);
		}
		if (!email) {
			throw new AuthError(AuthError.Messages.MissingEmail, 400);
		}
		if (!password) {
			throw new AuthError(AuthError.Messages.MissingPassword, 400);
		}
		if (typeof email !== 'string') {
			throw new AuthError(AuthError.Messages.InvalidEmail, 400);
		}
		if (typeof code !== 'string') {
			throw new AuthError(AuthError.Messages.InvalidCode, 400);
		}
		if (typeof password !== 'string') {
			throw new AuthError(AuthError.Messages.InvalidPassword, 400);
		}

		const dbCode = await db.getVerificationCode?.(email, code);
		if (!dbCode) {
			throw new AuthError(AuthError.Messages.InvalidCode, 400);
		}
		if (dbCode.expiresAt < new Date()) {
			throw new AuthError(AuthError.Messages.CodeExpired, 400);
		}
		const user = await db.getUserByEmail(email);
		let userId: string;
		if (user) {
			if (!addProvidersToExistingUsers || user.password) {
				throw new AuthError(AuthError.Messages.UserAlreadyExists, 409);
			} else {
				await db.updateUser(user.id, {
					emailVerifiedAt: new Date(),
					plaintextPassword: password,
				});
				userId = user.id;
			}
		} else {
			const user = await db.insertUser({
				fullName: dbCode.name,
				friendlyName: null,
				email,
				imageUrl: null,
				plaintextPassword: password,
				emailVerifiedAt: new Date(),
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
		const session = await sessions.createSession(userId, ctx);
		const sessionUpdate = await sessions.updateSession(session, ctx);
		return toRedirect(ctx, sessionUpdate);
	}

	async function handleEmailLoginRequest(ctx: Context) {
		const req = adapter.getRawRequest(ctx);
		const db = await getStorage(ctx);
		const formData = await req.formData();

		const email = formData.get('email');
		const password = formData.get('password');
		const returnTo = formData.get('returnTo') ?? undefined;
		const appState = formData.get('appState') ?? undefined;

		const params = z
			.object({
				email: z.string().email(),
				password: z.string().min(1),
				returnTo: z.string().optional().nullable(),
				appState: z.string().optional().nullable(),
			})
			.parse({ email, password, returnTo, appState });

		const user = await db.getUserByEmailAndPassword?.(
			params.email,
			params.password,
		);
		if (!user) {
			throw new AuthError(AuthError.Messages.InvalidPassword, 401);
		}
		const session = await sessions.createSession(user.id, ctx);
		const sessionUpdate = await sessions.updateSession(session, ctx);
		return toRedirect(ctx, sessionUpdate, {
			returnTo: resolveReturnTo(params.returnTo ?? undefined, ctx),
			appState: params.appState ?? undefined,
		});
	}

	async function handleResetPasswordRequest(ctx: Context) {
		const req = adapter.getRawRequest(ctx);
		const db = await getStorage(ctx);
		validateEmailConfig(db);
		const formData = await req.formData();

		const email = formData.get('email');
		const returnTo = formData.get('returnTo');
		const appState = formData.get('appState');

		const params = z
			.object({
				email: z.string().email(),
				returnTo: z.string().optional().nullable(),
				appState: z.string().optional().nullable(),
			})
			.parse({ email, returnTo, appState });

		const expiresAt = new Date();
		expiresAt.setHours(expiresAt.getHours() + 36);
		const code = Math.floor(Math.random() * 10000000).toString();
		await db.insertVerificationCode?.({
			email: params.email,
			code,
			expiresAt,
			name: '',
		});
		await emailService?.sendPasswordReset(
			{
				to: params.email,
				code,
				returnTo: resolveReturnTo(params.returnTo ?? undefined, ctx),
				appState: params.appState ?? undefined,
			},
			ctx,
		);

		return new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: {
				'content-type': 'application/json',
			},
		});
	}

	async function handleVerifyPasswordResetRequest(ctx: Context) {
		const req = adapter.getRawRequest(ctx);
		const db = await getStorage(ctx);
		validateEmailConfig(db);
		const formData = await req.formData();

		const email = formData.get('email');
		const returnTo = formData.get('returnTo');
		const appState = formData.get('appState');
		const newPassword = formData.get('newPassword');
		const code = formData.get('code');

		const params = z
			.object({
				email: z.string().email(),
				returnTo: z.string().optional().nullable(),
				appState: z.string().optional().nullable(),
				code: z.string().min(1),
				newPassword: z.string().min(5),
			})
			.parse({ email, returnTo, appState, newPassword, code });

		const dbCode = await db.getVerificationCode?.(params.email, params.code);
		if (!dbCode) {
			throw new AuthError(AuthError.Messages.InvalidCode, 400);
		}
		if (dbCode.expiresAt < new Date()) {
			throw new AuthError(AuthError.Messages.CodeExpired, 400);
		}

		const user = await db.getUserByEmail(params.email);
		if (!user) {
			throw new AuthError(AuthError.Messages.UserNotFound, 404);
		}

		await db.updateUser(user.id, {
			plaintextPassword: params.newPassword,
		});

		await db.consumeVerificationCode?.(params.email, params.code);

		const session = await sessions.createSession(user.id, ctx);
		const sessionUpdate = await sessions.updateSession(session, ctx);
		return toRedirect(ctx, sessionUpdate, {
			appState: params.appState ?? undefined,
			returnTo: resolveReturnTo(params.returnTo ?? undefined, ctx),
			message: 'Password reset successfully',
		});
	}

	async function handleSessionRequest(ctx: Context) {
		const session = await sessions.getSession(ctx);
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
			JSON.stringify({ session: getPublicSession(session, ctx) }),
			{
				status: 200,
				headers: {
					'content-type': 'application/json',
				},
			},
		);
	}

	async function handleRefreshSessionRequest(ctx: Context) {
		try {
			const { headers } = await sessions.refreshSession(ctx);
			headers.append('content-type', 'application/json');

			return new Response(
				JSON.stringify({
					ok: true,
				}),
				{
					status: 200,
					headers,
				},
			);
		} catch (err) {
			console.error('Refresh session error', err);
			if (err instanceof AuthError && err.statusCode === 401) {
				const { headers } = sessions.clearSession(ctx);
				headers.append('content-type', 'application/json');

				return new Response(
					JSON.stringify({
						ok: false,
					}),
					{
						status: 401,
						headers,
					},
				);
			}
			return new Response(
				JSON.stringify({
					ok: false,
				}),
				{
					status: 400,
					headers: {
						'content-type': 'application/json',
					},
				},
			);
		}
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
