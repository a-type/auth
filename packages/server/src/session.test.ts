import { serialize } from 'cookie';
import { randomUUID } from 'crypto';
import { SignJWT, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { SessionManager, defaultShortNames } from './session.js';

describe('Session tools', () => {
	const secret = 'supersecret';
	const getSessionConfig = (ctx: Request) => ({
		secret,
		cookieName: 'session',
		createSession: (id: string) => Promise.resolve({ userId: id }),
		audience: 'example.com',
		expiration: '1h',
		issuer: 'example.com',
		refreshPath: '/refresh',
		refreshTokenCookieName: 'refreshToken',
	});
	const sessions = new SessionManager<Request>({
		shortNames: defaultShortNames,
		getSessionConfig,
	});

	beforeAll(() => {
		vi.useFakeTimers({ now: new Date('2020-01-01T00:00:00Z') });
	});

	it('should refresh an expired JWT', async () => {
		const { headers: headersInit } = await sessions.updateSession(
			{
				userId: '123',
			},
			new Request('localhost:8080'),
		);
		let sessionHeaders = new Headers(headersInit);
		let cookies = sessionHeaders.get('Set-Cookie')!;

		const authToken = getCookie(cookies, 'session')!;
		const refreshToken = getCookie(cookies, 'refreshToken')!;

		expect(authToken).toBeTruthy();
		expect(refreshToken).toBeTruthy();

		expect(
			getFullCookie(cookies, 'session')?.includes(
				`Max-Age=1209600; Path=/; HttpOnly; SameSite=Lax`,
			),
		).toBeTruthy();
		expect(
			getFullCookie(cookies, 'refreshToken')?.includes(
				`Max-Age=1209600; Path=/refresh; HttpOnly; SameSite=Lax`,
			),
		).toBeTruthy();

		// verify refresh token cookie is scoped to the right path
		expect(sessionHeaders.get('Set-Cookie')!).toMatch(/Path=\/refresh/);

		// verify that the token is accepted
		let req = new Request('localhost:8080', {
			headers: new Headers({
				Cookie: serialize('session', authToken),
			}),
		});

		const session = await sessions.getSession(req);
		expect(session).not.toBe(null);
		expect(session!.userId).toBe('123');

		// advance past expiration
		vi.advanceTimersByTime(1000 * 60 * 60 * 2);

		// verify that the token is rejected
		await expect(sessions.getSession(req)).rejects.toThrowError(
			'Session expired',
		);

		// verify that the refresh token is accepted
		req = new Request('localhost:8080', {
			headers: new Headers({
				Cookie:
					serialize('session', authToken) +
					';' +
					serialize('refreshToken', refreshToken),
			}),
		});
		const { headers: newSessionHeadersInit } = await sessions.refreshSession(
			req,
		);
		sessionHeaders = new Headers(newSessionHeadersInit);
		cookies = sessionHeaders.get('Set-Cookie')!;

		const newAuthToken = getCookie(cookies, 'session')!;
		const newRefreshToken = getCookie(cookies, 'refreshToken')!;

		// verify that the new token is accepted
		req = new Request('localhost:8080', {
			headers: new Headers({
				Cookie:
					serialize('session', newAuthToken) +
					';' +
					serialize('refreshToken', newRefreshToken),
			}),
		});

		const newSession = await sessions.getSession(req);
		expect(newSession).not.toBe(null);
		expect(newSession!.userId).toBe('123');

		expect(newRefreshToken).not.toBe(refreshToken);
		expect(newRefreshToken).toBeTruthy();
	});

	it('should not allow refreshing any old token', async () => {
		const { headers: headersInit } = await sessions.updateSession(
			{
				userId: '123',
			},
			new Request('localhost:8080'),
		);
		const headers = new Headers(headersInit);
		const cookie = headers.get('Set-Cookie')!;
		const authToken = getCookie(cookie, 'session')!;
		const refreshToken = getCookie(cookie, 'refreshToken')!;

		expect(authToken).toBeTruthy();
		expect(refreshToken).toBeTruthy();

		// the JWT is in the cookie
		// for the sake of argument let's actually get the right JTI here
		// definitely test that the signature is checked
		const verifiedAuth = await jwtVerify(
			authToken,
			new TextEncoder().encode(secret),
			{
				issuer: 'example.com',
				audience: 'example.com',
			},
		);
		const jti = verifiedAuth.payload.jti!;
		// the refresh token is in the cookie

		// sign a JWT with some other signature
		const badToken = await new SignJWT({})
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setExpirationTime('24h')
			.setSubject('123')
			.setJti(jti)
			.sign(new TextEncoder().encode('blah'));

		const reqWithBadToken = new Request('localhost:8080', {
			headers: new Headers({
				Cookie:
					serialize('session', badToken) +
					';' +
					serialize('refreshToken', refreshToken),
			}),
		});

		// verify that the refresh token is rejected
		expect(sessions.refreshSession(reqWithBadToken)).rejects.toThrowError(
			'Invalid refresh token',
		);

		// even a token signed with the right signature whose JTI doesn't
		// match is rejected
		const newToken = await new SignJWT({})
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setExpirationTime('24h')
			.setSubject('123')
			.setJti(randomUUID())
			.sign(new TextEncoder().encode(secret));

		const reqWithNewToken = new Request('localhost:8080', {
			headers: new Headers({
				Cookie:
					serialize('session', newToken) +
					';' +
					serialize('refreshToken', refreshToken),
			}),
		});

		expect(sessions.refreshSession(reqWithNewToken)).rejects.toThrowError(
			'Invalid refresh token',
		);
	});
});

function getCookie(cookieHeader: string, name: string) {
	const match = getFullCookie(cookieHeader, name);
	if (!match) {
		return null;
	}

	const pieces = match.split(';');
	const value = pieces.shift()!.split('=')[1];
	return value;
}

function getFullCookie(cookieHeader: string, name: string) {
	const cookies = cookieHeader.split(',').map((c) => c.trim());
	const match = cookies.find((c) => c.startsWith(name));
	if (!match) {
		return null;
	}

	return match;
}
