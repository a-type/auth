import { parse } from 'cookie';
import { SignJWT, jwtVerify } from 'jose';

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
      shortNames: ShortNames;
      mode?: 'production' | 'development';
      createSession: (userId: string) => Promise<Session>;
      issuer?: string;
      audience?: string;
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

  getSession = async (req: Request) => {
    const cookieHeader = req.headers.get('cookie') ?? '';
    const cookies = parse(cookieHeader);
    const cookieValue = cookies[this.options.cookieName];
    if (!cookieValue) {
      return null;
    }
    // read the JWT from the cookie
    const jwt = await jwtVerify(cookieValue, this.secret, {
      issuer: this.options.issuer,
      audience: this.options.audience,
    });
    // convert the JWT claims to a session object
    const session: Session = Object.fromEntries(
      Object.entries(jwt).map(([key, value]) => [this.getLongName(key), value]),
    ) as any;
    // in dev mode, validate session has the right keys
    if (this.options.mode === 'development') {
      const keys = Object.keys(session);
      const expectedKeys = Object.keys(this.options.shortNames);
      if (keys.length !== expectedKeys.length) {
        throw new Error('Session has the wrong number of keys');
      }
      for (const key of keys) {
        if (!expectedKeys.includes(key)) {
          throw new Error(`Session has unexpected key: ${key}`);
        }
      }
    }
    return session;
  };

  updateSession = async (session: Session): Promise<Record<string, string>> => {
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
      .setExpirationTime('1h');

    if (this.options.issuer) {
      builder.setIssuer(this.options.issuer);
    }
    if (this.options.audience) {
      builder.setAudience(this.options.audience);
    }

    const jwt = await builder.sign(this.secret);
    return {
      'Set-Cookie': `${this.options.cookieName}=${jwt}; Path=/; HttpOnly; SameSite=Strict`,
    };
  };

  clearSession = (): Record<string, string> => {
    return {
      'Set-Cookie': `${this.options.cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
    };
  };

  private getShortName = (key: string) => {
    return (this.options.shortNames as any)[key];
  };
  private getLongName = (shortName: string) => {
    return this.shortNamesBackwards[shortName];
  };
}
