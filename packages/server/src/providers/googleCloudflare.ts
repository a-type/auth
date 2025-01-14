import { createRemoteJWKSet, jwtVerify } from 'jose';
import { AuthProvider, Profile, Tokens } from './types.js';

export class GoogleCloudflareProvider<Context = unknown>
	implements AuthProvider<Context>
{
	private getConfig;
	private jwks = createRemoteJWKSet(
		new URL('https://www.googleapis.com/oauth2/v3/certs'),
	);

	constructor({
		getConfig,
	}: {
		getConfig: (ctx: Context) => {
			clientId: string;
			clientSecret: string;
			redirectUri: string;
			state?: string;
		};
	}) {
		this.getConfig = getConfig;
	}

	getLoginUrl(ctx: Context): string {
		const config = this.getConfig(ctx);
		const url = new URL('https://accounts.google.com/o/oauth2/auth');
		const scopes = [
			'https://www.googleapis.com/auth/userinfo.email',
			'https://www.googleapis.com/auth/userinfo.profile',
		];
		const params = {
			client_id: config.clientId,
			redirect_uri: config.redirectUri,
			response_type: 'code',
			scope: scopes.join(' '),
			access_type: 'online',
			include_granted_scopes: 'true',
			state: config.state,
		};
		for (const [key, value] of Object.entries(params)) {
			if (value) {
				url.searchParams.append(key, value);
			}
		}
		return url.toString();
	}
	async getTokens(code: string, ctx: Context): Promise<Tokens> {
		const config = this.getConfig(ctx);
		const params = {
			client_id: config.clientId,
			client_secret: config.clientSecret,
			code,
			grant_type: 'authorization_code',
			redirect_uri: config.redirectUri,
		};
		const url = new URL('https://accounts.google.com/o/oauth2/token');

		const body = new FormData();
		for (const [key, value] of Object.entries(params)) {
			body.append(key, value);
		}

		const resp = await fetch(url.toString(), {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body,
		});

		if (!resp.ok) {
			throw new Error('Failed to fetch tokens');
		}

		const data = await resp.json();
		const tokens = {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			idToken: data.id_token,
			tokenType: data.token_type,
			scope: data.scope,
			expiresAt: new Date(Date.now() + data.expires_in * 1000),
		};

		if (tokens.idToken) {
			await this.verifyIdToken(tokens.idToken, ctx);
		}

		return tokens;
	}

	private verifyIdToken = async (idToken: string, ctx: Context) => {
		const config = this.getConfig(ctx);
		await jwtVerify(idToken, this.jwks, {
			issuer: 'https://accounts.google.com',
			audience: config.clientId,
		});
	};

	getProfile = async (accessToken: string, ctx: Context): Promise<Profile> => {
		const resp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
			headers: {
				Authorization: `Bearer ${accessToken}`,
			},
		});
		if (resp.status !== 200) {
			throw new Error('Failed to fetch profile');
		}
		const profile = (await resp.json()) as GoogleOAuthProfile;
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
