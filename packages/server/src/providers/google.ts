import { Auth, google } from 'googleapis';
import { AuthProvider, Profile, Tokens } from './types.js';

export class GoogleProvider<Context = unknown>
	implements AuthProvider<Context>
{
	private getConfig;
	private googleOauth: Auth.OAuth2Client | null = null;

	constructor({
		getConfig,
	}: {
		getConfig: (ctx: Context) => {
			clientId: string;
			clientSecret: string;
			redirectUri: string;
		};
	}) {
		this.getConfig = getConfig;
	}

	private getGoogleOAuth(ctx: Context) {
		if (this.googleOauth) {
			return this.googleOauth;
		}

		const { clientId, clientSecret, redirectUri } = this.getConfig(ctx);
		this.googleOauth = google.oauth2({
			version: 'v2',
			auth: new google.auth.OAuth2(clientId, clientSecret, redirectUri),
		}) as any;
		return this.googleOauth!;
	}

	getLoginUrl(ctx: Context): string {
		return this.getGoogleOAuth(ctx).generateAuthUrl({
			access_type: 'online',
			scope: [
				'https://www.googleapis.com/auth/userinfo.email',
				'https://www.googleapis.com/auth/userinfo.profile',
			],
			include_granted_scopes: true,
		});
	}
	async getTokens(code: string, ctx: Context): Promise<Tokens> {
		const { clientId } = this.getConfig(ctx);
		const tokens = await new Promise<Tokens>((resolve, reject) => {
			this.getGoogleOAuth(ctx).getToken(code, (err, tokens) => {
				if (err) {
					reject(err);
				} else if (!tokens) {
					reject(new Error('Failed to fetch tokens'));
				} else {
					resolve({
						accessToken: tokens.access_token!,
						refreshToken: tokens.refresh_token!,
						idToken: tokens.id_token!,
						tokenType: tokens.token_type!,
						scope: tokens.scope!,
						expiresAt: new Date(tokens.expiry_date!),
					});
				}
			});
		});

		if (tokens.idToken) {
			await this.getGoogleOAuth(ctx).verifyIdToken({
				idToken: tokens.idToken,
				audience: clientId,
			});
		}

		return tokens;
	}
	getProfile = async (accessToken: string, ctx: Context): Promise<Profile> => {
		this.getGoogleOAuth(ctx).setCredentials({ access_token: accessToken });
		const resp = await this.getGoogleOAuth(ctx).request({
			url: 'https://www.googleapis.com/oauth2/v3/userinfo',
		});
		if (resp.status !== 200) {
			throw new Error('Failed to fetch profile');
		}
		const profile = resp.data as GoogleOAuthProfile;
		return {
			id: profile.sub,
			fullName: profile.name,
			friendlyName: profile.given_name,
			email: profile.email,
			avatarUrl: profile.picture,
		};
	};
}

type GoogleOAuthProfile = {
	sub: string;
	name: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	email: string;
	email_verified: boolean;
	locale: string;
};
