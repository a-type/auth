import cookie from 'cookie';

export const RETURN_TO_COOKIE = 'return-to';

export function getReturnTo(req: Request) {
  const cookies = cookie.parse(req.headers.get('cookie') ?? '');
  const cookieVal = cookies[RETURN_TO_COOKIE];
  if (typeof cookieVal === 'string') {
    return cookieVal;
  }
  // check for query param
  const url = new URL(req.url);
  return url.searchParams.get('returnTo') ?? undefined;
}

export function setReturnTo(
  res: Response,
  returnTo: string,
  sameSite: 'strict' | 'lax' | 'none' = 'lax',
) {
  res.headers.append(
    'Set-Cookie',
    cookie.serialize(RETURN_TO_COOKIE, returnTo, {
      path: '/',
      httpOnly: true,
      sameSite,
      expires: new Date(Date.now() + 1000 * 30),
    }),
  );
}

export const APP_STATE_COOKIE = 'app-state';

export function getAppState(req: Request): string | undefined {
  const cookies = cookie.parse(req.headers.get('cookie') ?? '');
  const cookieVal = cookies[APP_STATE_COOKIE];
  if (typeof cookieVal === 'string') {
    return cookieVal;
  }
  // check for query param
  const url = new URL(req.url);
  return url.searchParams.get('appState') ?? undefined;
}

export function setAppState(
  res: Response,
  appState: string | undefined | null,
  sameSite: 'strict' | 'lax' | 'none' = 'lax',
) {
  if (appState) {
    res.headers.append(
      'Set-Cookie',
      cookie.serialize(APP_STATE_COOKIE, appState, {
        path: '/',
        httpOnly: true,
        sameSite,
        expires: new Date(Date.now() + 1000 * 30),
      }),
    );
  }
}
