import { AuthProvider, Profile, Tokens } from './types.js';
import Discord from 'discord-oauth2';

export class DiscordProvider implements AuthProvider {
  private discordAuth;

  constructor({
    clientId,
    clientSecret,
    redirectUri,
  }: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }) {
    this.discordAuth = new Discord({
      clientId,
      clientSecret,
      redirectUri,
    });
  }

  getLoginUrl(): string {
    return this.discordAuth.generateAuthUrl({
      scope: ['identify', 'email'],
    });
  }

  async getTokens(code: string): Promise<Tokens> {
    const res = await this.discordAuth.tokenRequest({
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
      expiresAt: res.expires_in,
    };
  }
  async getProfile(accessToken: string): Promise<Profile> {
    const profile = await this.discordAuth.getUser(accessToken);
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
