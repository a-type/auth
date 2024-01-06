export interface AuthProvider {
  getLoginUrl(): string;
  getTokens(code: string): Promise<Tokens>;
  getProfile(accessToken: string): Promise<Profile>;
}

export interface Profile {
  id: string;
  fullName: string;
  friendlyName?: string;
  email: string;
  avatarUrl?: string;
  emailVerified?: boolean;
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  idToken?: string;
  tokenType: string;
  scope: string;
  expiresAt: number;
}
