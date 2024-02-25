import { it, describe, vi, beforeAll, expect } from 'vitest';
import { SessionManager, defaultShortNames } from './session.js';
import { parse } from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import { randomUUID } from 'crypto';

describe('Session tools', () => {
  const secret = 'supersecret';
  const sessions = new SessionManager({
    secret,
    cookieName: 'session',
    createSession: (id) => Promise.resolve({ userId: id }),
    shortNames: defaultShortNames,
    audience: 'example.com',
    expiration: '1h',
    issuer: 'example.com',
  });

  beforeAll(() => {
    vi.useFakeTimers({ now: new Date('2020-01-01T00:00:00Z') });
  });

  it('should refresh an expired JWT', async () => {
    const headers = await sessions.updateSession(
      { userId: '123' },
      {
        sendRefreshToken: true,
      },
    );

    // the JWT is in the cookie, the refresh token is on X-Refresh-Token
    const cookies = parse(headers['Set-Cookie']);
    const authToken = cookies['session'];
    const refreshToken = headers['x-refresh-token'];

    // verify that the token is accepted
    let req = {
      headers: new Headers({
        Cookie: `session=${authToken}`,
      }),
    };

    const session = await sessions.getSession(req);
    expect(session).not.toBe(null);
    expect(session!.userId).toBe('123');

    // advance past expiration
    vi.advanceTimersByTime(1000 * 60 * 60 * 2);

    // verify that the token is rejected
    req = {
      headers: new Headers({
        Cookie: `session=${authToken}`,
      }),
    };

    expect(sessions.getSession(req)).rejects.toThrowError('Session expired');

    // verify that the refresh token is accepted
    const newSessionHeaders = await sessions.refreshSession(
      authToken,
      refreshToken,
    );

    // the new JWT is in the cookie, the new refresh token is on X-Refresh-Token
    const newCookies = parse(newSessionHeaders['Set-Cookie']);
    const newAuthToken = newCookies['session'];
    const newRefreshToken = newSessionHeaders['x-refresh-token'];

    // verify that the new token is accepted
    req = {
      headers: new Headers({
        Cookie: `session=${newAuthToken}`,
      }),
    };

    const newSession = await sessions.getSession(req);
    expect(newSession).not.toBe(null);
    expect(newSession!.userId).toBe('123');

    expect(newRefreshToken).not.toBe(refreshToken);
    expect(newRefreshToken).toBeTruthy();
  });

  it('should not allow refreshing any old token', async () => {
    const headers = await sessions.updateSession(
      { userId: '123' },
      {
        sendRefreshToken: true,
      },
    );

    // the JWT is in the cookie, the refresh token is on X-Refresh-Token
    const cookies = parse(headers['Set-Cookie']);
    const authToken = cookies['session'];
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
    const refreshToken = headers['x-refresh-token'];

    // sign a JWT with some other signature
    const badToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('24h')
      .setSubject('123')
      .setJti(jti)
      .sign(new TextEncoder().encode('blah'));

    // verify that the refresh token is rejected
    expect(
      sessions.refreshSession(badToken, refreshToken),
    ).rejects.toThrowError('signature verification failed');

    // even a token signed with the right signature whose JTI doesn't
    // match is rejected
    const newToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('24h')
      .setSubject('123')
      .setJti(randomUUID())
      .sign(new TextEncoder().encode(secret));

    expect(
      sessions.refreshSession(newToken, refreshToken),
    ).rejects.toThrowError('Invalid refresh token');
  });
});
