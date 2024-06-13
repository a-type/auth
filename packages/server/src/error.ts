export enum ErrorMessages {
  InvalidPassword = 'Invalid email or password',
  UserAlreadyExists = 'User already exists',
  CodeExpired = 'Code expired',
  InvalidCode = 'Invalid code',
  InvalidEmail = 'Invalid email',
  MissingPassword = 'Missing password',
  MissingEmail = 'Missing email',
  MissingCode = 'Missing code',
}

export class AuthError extends Error {
  static Messages = ErrorMessages;
  constructor(message: string, public statusCode: number) {
    super(message);
  }

  toResponse() {
    return new Response(this.message, {
      status: this.statusCode,
    });
  }
}
