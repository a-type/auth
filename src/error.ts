export class AuthError extends Error {
  constructor(message: string, public statusCode: number) {
    super(message);
  }
}
