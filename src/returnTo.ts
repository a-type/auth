import cookie from 'cookie';

export const RETURN_TO_COOKIE = 'return-to';

export function getReturnTo(req: Request) {
  const cookies = cookie.parse(req.headers.get('cookie') ?? '');
  return cookies[RETURN_TO_COOKIE] ?? '/';
}
