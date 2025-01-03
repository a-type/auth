export interface AuthProvider<Context = unknown> {
	getLoginUrl(ctx: Context): string;
	getTokens(code: string, ctx: Context): Promise<Tokens>;
	getProfile(accessToken: string, ctx: Context): Promise<Profile>;
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
	expiresAt: Date;
}
