export enum ErrorMessages {
  InvalidPassword = 'Invalid email or password',
  UserAlreadyExists = 'User already exists',
  CodeExpired = 'Code expired',
  InvalidCode = 'Invalid code',
  InvalidEmail = 'Invalid email',
  InvalidName = 'Invalid name',
  MissingPassword = 'Missing password',
  MissingEmail = 'Missing email',
  MissingCode = 'Missing code',
  SessionExpired = 'Session expired',
  InternalError = 'Internal error',
  InvalidSession = 'Invalid session',
  InvalidRefreshToken = 'Invalid refresh token',
  RefreshTokenExpired = 'Refresh token expired',
  UserNotFound = 'User not found',
}

function kebabCase(str: string) {
  return str.replace(/\s/g, '-').toLowerCase();
}

export class AuthError extends Error {
  static Messages = ErrorMessages;
  constructor(message: string, public statusCode: number) {
    super(message);
  }

  toResponse() {
    return new Response(this.message, {
      status: this.statusCode,
      headers: new Headers({
        'x-auth-error': kebabCase(this.message),
      }),
    });
  }
}
