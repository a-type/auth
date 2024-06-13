export interface AuthDB {
  insertUser(
    user: Omit<AuthUser, 'id' | 'password'> & {
      plaintextPassword: string | null;
    },
  ): Promise<Pick<AuthUser, 'id'>>;
  updateUser(
    userId: string,
    user: Partial<
      Omit<AuthUser, 'id' | 'email' | 'password'> & {
        plaintextPassword: string | null;
      }
    >,
  ): Promise<void>;
  insertAccount(
    account: Omit<AuthAccount, 'id'>,
  ): Promise<Pick<AuthAccount, 'id'>>;
  getUserByEmail(email: string): Promise<AuthUser | undefined>;
  getAccountByProviderAccountId(
    provider: string,
    providerAccountId: string,
  ): Promise<AuthAccount | undefined>;
  insertVerificationCode?(data: AuthVerificationCode): Promise<void>;
  consumeVerificationCode?(email: string, code: string): Promise<void>;
  getVerificationCode?(
    email: string,
    code: string,
  ): Promise<AuthVerificationCode | undefined>;
  getUserByEmailAndPassword?(
    email: string,
    password: string,
  ): Promise<AuthUser | undefined>;
}

export interface AuthUser {
  id: string;
  fullName: string | null;
  friendlyName: string | null;
  email: string;
  emailVerifiedAt: string | null;
  imageUrl: string | null;
  /** the hashed password, please. */
  password: string | null;
}

export interface AuthAccount {
  id: string;
  userId: string;
  type: string;
  provider: string;
  providerAccountId: string;
  refreshToken: string | null;
  accessToken: string | null;
  expiresAt: number | null;
  tokenType: string | null;
  scope: string | null;
  idToken: string | null;
}

export interface AuthVerificationCode {
  email: string;
  code: string;
  expiresAt: number;
  name: string;
}