import { parse, serialize } from 'cookie';
import { randomUUID } from 'crypto';
import {
	compactVerify,
	decodeJwt,
	errors,
	JWTPayload,
	jwtVerify,
	SignJWT,
} from 'jose';
import { rawAdapter, ServerAdapter } from './adapter.js';
import { AuthError } from './error.js';

export interface Session {
	userId: string;
}

export type ShortNames = {
	[key in keyof Session]: string;
};

export const defaultShortNames = {
	userId: 'sub',
};

const textEncoder = new TextEncoder();

export class SessionManager<Context = unknown> {
	private shortNamesBackwards: Record<string, keyof Session>;
	private getSessionConfig;
	private adapter;
	private shortNames = defaultShortNames;

	constructor(options: {
		adapter?: ServerAdapter<Context>;
		getSessionConfig: (ctx: Context) => {
			secret: string;
			cookieName: string;
			refreshTokenDurationMinutes?: number;
			/**
			 * The HTTP request path the client will make a request to
			 * when refreshing their session. The refresh token cookie
			 * is limited to this path to prevent sending it in every
			 * request.
			 */
			refreshPath: string;
			refreshTokenCookieName: string;
			mode?: 'production' | 'development';
			createSession: (userId: string) => Promise<Session>;
			issuer?: string;
			audience?: string;
			expiration?: string;
			cookieOptions?: {
				partitioned?: boolean;
				sameSite?: 'strict' | 'lax' | 'none';
				/**
				 * Allows specifying a domain for the cookie besides the one serving the request. This allows setting
				 * cookies for the root domain from a subdomain, for example.
				 */
				domain?: string;
				/**
				 * The path the cookie is limited to. Defaults to `/` to allow the cookie to be sent with all requests.
				 * Not recommended to change this unless you have a specific reason to do so.
				 */
				path?: string;
			};
		};
		shortNames?: ShortNames;
	}) {
		this.getSessionConfig = options.getSessionConfig;
		this.adapter = options.adapter ?? (rawAdapter as ServerAdapter<Context>);
		this.shortNames = options.shortNames ?? defaultShortNames;
		this.shortNamesBackwards = Object.fromEntries(
			Object.entries(this.shortNames).map(([key, value]) => [value, key]),
		) as any;
		// validate shortnames don't repeat
		const values = Object.values(this.shortNames);
		if (new Set(values).size !== values.length) {
			throw new Error('Short names must be unique');
		}
	}

	public getIsSameSite = (ctx: Context) => {
		const { cookieOptions } = this.getSessionConfig(ctx);
		return cookieOptions?.sameSite ?? 'lax';
	};
	getIsPartitioned = (ctx: Context) => {
		const { cookieOptions } = this.getSessionConfig(ctx);
		return cookieOptions?.partitioned ?? this.getIsSameSite(ctx) === 'none';
	};

	createSession = async (userId: string, ctx: Context): Promise<Session> => {
		const { createSession } = this.getSessionConfig(ctx);
		return createSession(userId);
	};

	getAccessToken = (ctx: Context) => {
		const { cookieName } = this.getSessionConfig(ctx);
		const req = this.adapter.getRawRequest(ctx);
		const cookieHeader = req.headers.get('cookie') ?? '';
		const cookies = parse(cookieHeader);
		const cookieValue = cookies[cookieName];
		if (!cookieValue) {
			return null;
		}
		return cookieValue;
	};

	getRefreshToken = (ctx: Context) => {
		const { refreshTokenCookieName } = this.getSessionConfig(ctx);
		const req = this.adapter.getRawRequest(ctx);
		const cookieHeader = req.headers.get('cookie') ?? '';
		const cookies = parse(cookieHeader);
		const cookieValue = cookies[refreshTokenCookieName];
		if (!cookieValue) {
			return null;
		}
		return cookieValue;
	};

	getSession = async (ctx: Context) => {
		const { secret, issuer, audience, mode } = this.getSessionConfig(ctx);
		const encodedSecret = textEncoder.encode(secret);
		const cookieValue = this.getAccessToken(ctx);
		if (!cookieValue) return null;

		// read the JWT from the cookie
		try {
			const jwt = await jwtVerify(cookieValue, encodedSecret, {
				issuer,
				audience,
			});
			// convert the JWT claims to a session object
			const session: Session = this.readSessionFromPayload(jwt.payload);
			// in dev mode, validate session has the right keys
			if (mode === 'development') {
				const keys = Object.keys(session);
				const expectedKeys = Object.keys(this.shortNames);
				for (const key of expectedKeys) {
					if (!keys.includes(key)) {
						console.error(`Session missing expected key: ${key}`);
						throw new AuthError(AuthError.Messages.InvalidSession, 400);
					}
				}
			}
			return session;
		} catch (e) {
			// if the JWT is expired, throw a specific error.
			// if it's otherwise invalid, throw a different one.
			if (e instanceof errors.JWTExpired) {
				throw new AuthError(AuthError.Messages.SessionExpired, 401, e);
			} else if (
				e instanceof errors.JWTInvalid ||
				e instanceof errors.JWSInvalid ||
				e instanceof errors.JWKSInvalid ||
				e instanceof errors.JWSSignatureVerificationFailed ||
				e instanceof errors.JWTClaimValidationFailed
			) {
				throw new AuthError(AuthError.Messages.InvalidSession, 400, e);
			}
			throw new AuthError(AuthError.Messages.InternalError, 500, e);
		}
	};

	/**
	 * Refresh the session by re-signing the JWT with a new expiration time.
	 * Requires a valid refresh token.
	 */
	refreshSession = async (ctx: Context) => {
		const accessToken = this.getAccessToken(ctx);
		const refreshToken = this.getRefreshToken(ctx);

		if (!accessToken) {
			throw new AuthError(AuthError.Messages.InvalidSession, 400);
		}
		if (!refreshToken) {
			throw new AuthError(AuthError.Messages.InvalidRefreshToken, 400);
		}

		const { secret, issuer, audience } = this.getSessionConfig(ctx);
		const encodedSecret = textEncoder.encode(secret);
		try {
			const refreshData = await jwtVerify(refreshToken, encodedSecret, {
				issuer,
				audience,
			});

			// verify the signature of the token
			await compactVerify(accessToken, encodedSecret);

			const accessData = decodeJwt(accessToken);

			if (refreshData.payload.jti !== accessData.jti) {
				throw new AuthError(AuthError.Messages.InvalidRefreshToken, 400);
			}

			const session = this.readSessionFromPayload(accessData);

			return this.updateSession(session, ctx);
		} catch (err) {
			if (
				err instanceof Error &&
				(err.message.includes('JWTExpired') ||
					err.name === 'JWTExpired' ||
					err instanceof errors.JWTExpired)
			) {
				throw new AuthError(AuthError.Messages.RefreshTokenExpired, 401, err);
			}
			throw new AuthError(AuthError.Messages.InvalidRefreshToken, 400, err);
		}
	};

	updateSession = async (
		session: Session,
		ctx: Context,
	): Promise<{ headers: Headers }> => {
		const {
			secret,
			cookieName,
			cookieOptions,
			mode,
			refreshTokenCookieName,
			refreshPath,
		} = this.getSessionConfig(ctx);
		const encodedSecret = textEncoder.encode(secret);
		const headers = new Headers();

		const jti = randomUUID();
		const accessTokenBuilder = this.getAccessTokenBuilder(session, jti, ctx);
		const jwt = await accessTokenBuilder.sign(encodedSecret);

		const sameSite = this.getIsSameSite(ctx);

		const authCookie = serialize(cookieName, jwt, {
			httpOnly: true,
			sameSite,
			path: cookieOptions?.path ?? '/',
			domain: cookieOptions?.domain,
			secure: mode === 'production',
			// sync access token expiration to refresh token - an expired token
			// will still be presented to the server, but the server will reject it
			// as expired. the api can then tell the client the token is expired
			// and the refresh should be used. once the access token cookie is expired
			// and removed, it will instead trigger a fully logged out state.
			expires: this.getRefreshTokenExpirationTime(ctx),
		});
		headers.append('Set-Cookie', authCookie);

		const refreshTokenBuilder = this.getRefreshTokenBuilder(jti, ctx);
		const refreshToken = await refreshTokenBuilder.sign(encodedSecret);
		const refreshCookie = serialize(refreshTokenCookieName, refreshToken, {
			httpOnly: true,
			sameSite,
			path: refreshPath,
			secure: mode === 'production',
			expires: this.getRefreshTokenExpirationTime(ctx),
			partitioned: this.getIsPartitioned(ctx),
			domain: cookieOptions?.domain,
		});
		headers.append('Set-Cookie', refreshCookie);

		return {
			headers,
		};
	};

	clearSession = (ctx: Context): { headers: Headers } => {
		const {
			cookieName,
			mode,
			refreshTokenCookieName,
			refreshPath,
			cookieOptions,
		} = this.getSessionConfig(ctx);
		const headers = new Headers();
		const sameSite = this.getIsSameSite(ctx);
		const cookie = serialize(cookieName, '', {
			httpOnly: true,
			sameSite,
			path: '/',
			secure: mode === 'production',
			expires: new Date(0),
			domain: cookieOptions?.domain,
		});
		headers.append('Set-Cookie', cookie);
		const refreshCookie = serialize(refreshTokenCookieName, '', {
			httpOnly: true,
			sameSite,
			path: refreshPath,
			secure: mode === 'production',
			expires: new Date(0),
			partitioned: this.getIsPartitioned(ctx),
			domain: cookieOptions?.domain,
		});
		headers.append('Set-Cookie', refreshCookie);
		return {
			headers,
		};
	};

	private getAccessTokenBuilder = (
		session: Session,
		jti: string,
		ctx: Context,
	) => {
		const { expiration, issuer, audience } = this.getSessionConfig(ctx);
		const builder = new SignJWT(
			Object.fromEntries(
				Object.entries(session).map(([key, value]) => [
					this.getShortName(key),
					value,
				]),
			) as any,
		)
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setExpirationTime(expiration ?? '12h')
			.setSubject(session.userId)
			.setJti(jti);

		if (issuer) {
			builder.setIssuer(issuer);
		}
		if (audience) {
			builder.setAudience(audience);
		}
		return builder;
	};

	private getRefreshTokenBuilder = (jti: string, ctx: Context) => {
		const { issuer, audience } = this.getSessionConfig(ctx);
		const refreshTokenBuilder = new SignJWT({
			jti,
		})
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setExpirationTime(this.getRefreshTokenExpirationTime(ctx));

		if (issuer) {
			refreshTokenBuilder.setIssuer(issuer);
		}
		if (audience) {
			refreshTokenBuilder.setAudience(audience);
		}

		return refreshTokenBuilder;
	};

	private getRefreshTokenExpirationTime = (ctx: Context) => {
		const { refreshTokenDurationMinutes } = this.getSessionConfig(ctx);
		const msFromNow = (refreshTokenDurationMinutes ?? 60 * 24 * 14) * 60 * 1000;
		return new Date(Date.now() + msFromNow);
	};

	private getShortName = (key: string) => {
		return (this.shortNames as any)[key];
	};
	private getLongName = (shortName: string) => {
		return this.shortNamesBackwards[shortName];
	};

	private readSessionFromPayload = (jwt: JWTPayload): Session => {
		return Object.fromEntries(
			Object.entries(jwt).map(([key, value]) => [this.getLongName(key), value]),
		) as any;
	};
}
