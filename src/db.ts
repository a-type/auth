export interface AuthDB {
  insertUser(
    user: Omit<AuthUser, 'id'> & { plaintextPassword: string | null },
  ): Promise<Pick<AuthUser, 'id'>>;
  insertAccount(
    account: Omit<AuthAccount, 'id'>,
  ): Promise<Pick<AuthAccount, 'id'>>;
  getUserByEmail(email: string): Promise<AuthUser | undefined>;
  getAccountByProviderAccountId(
    provider: string,
    providerAccountId: string,
  ): Promise<AuthAccount | undefined>;
  insertVerificationCode?(data: AuthVerificationCode): Promise<void>;
  getVerificationCode?(
    email: string,
    code: string,
  ): Promise<AuthVerificationCode>;
  getUserByEmailAndPassword?(
    email: string,
    password: string,
  ): Promise<AuthUser>;
}

export interface AuthUser {
  id: string;
  fullName: string | null;
  friendlyName: string | null;
  email: string;
  emailVerifiedAt: string | null;
  imageUrl: string | null;
}

export interface AuthAccount {
  id: string;
  userId: string;
  type: 'email' | 'oidc' | 'oauth';
  provider: string;
  providerAccountId: string;
  refreshToken: string | undefined;
  accessToken: string | undefined;
  expiresAt: number | undefined;
  tokenType: string | undefined;
  scope: string | undefined;
  idToken: string | undefined;
}

export interface AuthVerificationCode {
  email: string;
  code: string;
  expiresAt: number;
  name: string;
}
