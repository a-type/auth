import Discord from 'discord-oauth2';
import { AuthProvider, Profile, Tokens } from './types.js';

export class DiscordProvider<Context = unknown>
	implements AuthProvider<Context>
{
	private discordAuth: Discord | null = null;
	private getConfig;

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

	private getDiscordAuth(ctx: Context) {
		if (this.discordAuth) {
			return this.discordAuth;
		}

		const { clientId, clientSecret, redirectUri } = this.getConfig(ctx);
		this.discordAuth = new Discord({
			clientId,
			clientSecret,
			redirectUri,
		});
		return this.discordAuth;
	}

	getLoginUrl(ctx: Context): string {
		return this.getDiscordAuth(ctx).generateAuthUrl({
			scope: ['identify', 'email'],
		});
	}

	async getTokens(code: string, ctx: Context): Promise<Tokens> {
		const res = await this.getDiscordAuth(ctx).tokenRequest({
			code,
			scope: ['identify', 'email'],
			grantType: 'authorization_code',
		});

		return {
			accessToken: res.access_token,
			refreshToken: res.refresh_token,
			// idToken: res.id_token,
			tokenType: res.token_type,
			scope: res.scope,
			// TODO: is this right?
			expiresAt: new Date(res.expires_in),
		};
	}
	async getProfile(accessToken: string, ctx: Context): Promise<Profile> {
		const profile = await this.getDiscordAuth(ctx).getUser(accessToken);
		if (!profile.email) {
			throw new Error('Failed to fetch profile: email not provided');
		}
		return {
			email: profile.email,
			fullName: profile.username,
			friendlyName: profile.username,
			id: profile.id,
			avatarUrl: profile.avatar ?? undefined,
		};
	}
}
