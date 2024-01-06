import { getIronSession } from 'iron-session';

const SESSION_COOKIE = 'lg-session';

const SESSION_SECRET = process.env.SESSION_SECRET!;
if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set');
}

export interface Session {
  userId: string;
}

export async function getLiveSession(
  req: Request,
  res: Response,
): Promise<Session | null> {
  const rawSession = await getOrCreateSession(req, res);
  if (!rawSession.userId) {
    return null;
  }
  return rawSession as Session;
}

export function getOrCreateSession(req: Request, res: Response) {
  return getIronSession<Partial<Session>>(req, res, {
    cookieName: SESSION_COOKIE,
    password: SESSION_SECRET,
  });
}
