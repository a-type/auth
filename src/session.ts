import { parse, serialize } from 'cookie';
import {
  SignJWT,
  jwtVerify,
  decodeJwt,
  errors,
  JWTPayload,
  compactVerify,
} from 'jose';
import { AuthError } from './error.js';
import { randomUUID } from 'crypto';

export interface Session {
  userId: string;
}

export type ShortNames = {
  [key in keyof Session]: string;
};

export const defaultShortNames = {
  userId: 'sub',
};

export class SessionManager {
  private secret;
  private shortNamesBackwards: Record<string, keyof Session>;

  constructor(
    private options: {
      secret: string;
      cookieName: string;
      refreshParam?: string;
      /** format like '7d' */
      refreshTokenDuration?: string;
      shortNames: ShortNames;
      mode?: 'production' | 'development';
      createSession: (userId: string) => Promise<Session>;
      issuer?: string;
      audience?: string;
      expiration?: string;
      /** Specify a client domain */
      clientDomain?: string;
    },
  ) {
    this.secret = new TextEncoder().encode(options.secret);
    this.shortNamesBackwards = Object.fromEntries(
      Object.entries(options.shortNames).map(([key, value]) => [value, key]),
    ) as any;
    // validate shortnames don't repeat
    const values = Object.values(options.shortNames);
    if (new Set(values).size !== values.length) {
      throw new Error('Short names must be unique');
    }
  }

  createSession = async (userId: string): Promise<Session> => {
    return this.options.createSession(userId);
  };

  getAccessToken = (req: { headers: Headers }) => {
    const cookieHeader = req.headers.get('cookie') ?? '';
    const cookies = parse(cookieHeader);
    const cookieValue = cookies[this.options.cookieName];
    if (!cookieValue) {
      return null;
    }
    return cookieValue;
  };

  getRefreshToken = (req: { headers: Headers }) => {
    return req.headers.get('x-refresh-token');
  };

  getSession = async (req: { headers: Headers }) => {
    const cookieValue = this.getAccessToken(req);
    if (!cookieValue) return null;

    // read the JWT from the cookie
    try {
      const jwt = await jwtVerify(cookieValue, this.secret, {
        issuer: this.options.issuer,
        audience: this.options.audience,
      });
      // convert the JWT claims to a session object
      const session: Session = this.readSessionFromPayload(jwt.payload);
      // in dev mode, validate session has the right keys
      if (this.options.mode === 'development') {
        const keys = Object.keys(session);
        const expectedKeys = Object.keys(this.options.shortNames);
        for (const key of expectedKeys) {
          if (!keys.includes(key)) {
            throw new Error(`Session missing unexpected key: ${key}`);
          }
        }
      }
      return session;
    } catch (e) {
      // if the JWT is expired, throw a specific error.
      // if it's otherwise invalid, throw a different one.
      if (e instanceof errors.JWTExpired) {
        throw new AuthError('Session expired', 401);
      } else if (
        e instanceof errors.JWTInvalid ||
        e instanceof errors.JWSInvalid
      ) {
        throw new AuthError('Invalid session', 400);
      }
      throw e;
    }
  };

  /**
   * Refresh the session by re-signing the JWT with a new expiration time.
   * Requires a valid refresh token.
   */
  refreshSession = async (accessToken: string, refreshToken: string) => {
    const refreshData = await jwtVerify(refreshToken, this.secret, {
      issuer: this.options.issuer,
      audience: this.options.audience,
    });

    // verify the signature of the token
    await compactVerify(accessToken, this.secret);

    const accessData = decodeJwt(accessToken);

    if (refreshData.payload.jti !== accessData.jti) {
      throw new AuthError('Invalid refresh token', 400);
    }

    const session = this.readSessionFromPayload(accessData);

    return this.updateSession(session, { sendRefreshToken: true });
  };

  updateSession = async (
    session: Session,
    {
      sendRefreshToken,
    }: {
      sendRefreshToken?: boolean;
    } = { sendRefreshToken: false },
  ) => {
    const jti = randomUUID();
    const accessTokenBuilder = this.getAccessTokenBuilder(session, jti);
    const jwt = await accessTokenBuilder.sign(this.secret);
    const parsed = decodeJwt(jwt);

    const authCookie = serialize(this.options.cookieName, jwt, {
      httpOnly: true,
      sameSite: 'strict',
      path: '/',
      secure: this.options.mode === 'production',
      // add a bit of buffer.
      expires: parsed.exp
        ? new Date(parsed.exp * 1000 + 300 * 1000)
        : undefined,
    });
    const headers: Record<string, string> = {
      'Set-Cookie': authCookie,
    };
    const searchParams = new URLSearchParams();

    if (sendRefreshToken) {
      const refreshTokenBuilder = this.getRefreshTokenBuilder(jti);
      const refreshToken = await refreshTokenBuilder.sign(this.secret);
      const parsed = decodeJwt(refreshToken);
      searchParams.set(this.refreshParam, refreshToken);
      if (parsed.exp) {
        searchParams.set('refreshTokenExpires', `${parsed.exp}`);
      }
    }

    return {
      headers,
      searchParams,
    };
  };

  clearSession = () => {
    return {
      headers: {
        'Set-Cookie': `${this.options.cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      },
    };
  };

  private getAccessTokenBuilder = (session: Session, jti: string) => {
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
      .setExpirationTime(this.options.expiration ?? '12h')
      .setSubject(session.userId)
      .setJti(jti);

    if (this.options.issuer) {
      builder.setIssuer(this.options.issuer);
    }
    if (this.options.audience) {
      builder.setAudience(this.options.audience);
    }
    return builder;
  };

  private getRefreshTokenBuilder = (jti: string) => {
    const refreshTokenBuilder = new SignJWT({
      jti,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime(this.options.refreshTokenDuration ?? '14d');

    if (this.options.issuer) {
      refreshTokenBuilder.setIssuer(this.options.issuer);
    }
    if (this.options.audience) {
      refreshTokenBuilder.setAudience(this.options.audience);
    }

    return refreshTokenBuilder;
  };

  private getShortName = (key: string) => {
    return (this.options.shortNames as any)[key];
  };
  private getLongName = (shortName: string) => {
    return this.shortNamesBackwards[shortName];
  };

  private readSessionFromPayload = (jwt: JWTPayload): Session => {
    return Object.fromEntries(
      Object.entries(jwt).map(([key, value]) => [this.getLongName(key), value]),
    ) as any;
  };

  private get refreshParam() {
    return this.options.refreshParam ?? `refreshToken`;
  }
}
