export interface EmailProvider<Context = unknown> {
	sendMail: (
		args: {
			from: string;
			to: string;
			subject: string;
			text: string;
			html: string;
		},
		ctx: Context,
	) => Promise<void>;
}

export class Email<Context = unknown> {
	constructor(
		private config: {
			provider: EmailProvider<Context>;
			getConfig: (ctx: Context) => Promise<{
				uiOrigin: string;
				from: string;
				appName: string;
				developerName?: string;
			}>;
		},
	) {}

	sendEmailVerification = async (
		{ to, code }: { to: string; code: string },
		ctx: Context,
	) => {
		const info = await this.config.getConfig(ctx);
		const url = new URL('/verify', info.uiOrigin);
		url.searchParams.set('code', code);
		url.searchParams.set('email', to);
		await this.config.provider.sendMail(
			{
				from: info.from,
				to,
				subject: `Verify your email on ${info.appName}`,
				text: `Visit ${url} to verify your email.`,
				html: `
			<div>
				<h1>Thanks for signing up to ${info.appName}!</h1>
				<p>Click the button below to finish signing up on this device.</p>
				<a href="${url}">Verify my email</a>
				<p>After that, you can sign in on any device you want!</p>
				<p>If you didn't request this email, you can safely ignore it.</p>
				<p>Thanks,</p>
				<p>${info.developerName ?? `The ${info.appName} Team`}</p>
			</div>`,
			},
			ctx,
		);
	};

	sendPasswordReset = async (
		{
			to,
			code,
			returnTo,
			appState,
		}: {
			to: string;
			code: string;
			returnTo?: string;
			appState?: string;
		},
		ctx: Context,
	) => {
		const info = await this.config.getConfig(ctx);
		const url = new URL('/reset-password', info.uiOrigin);
		url.searchParams.set('code', code);
		url.searchParams.set('email', to);
		if (returnTo) {
			url.searchParams.set('returnTo', returnTo);
		}
		if (appState) {
			url.searchParams.set('appState', appState);
		}

		await this.config.provider.sendMail(
			{
				from: info.from,
				to,
				subject: `Reset your password on ${info.appName}`,
				text: `Visit ${url} to reset your password.`,
				html: `
			<div>
				<h1>Reset your password on ${info.appName}</h1>
				<p>Click the link below to reset your password.</p>
				<a href="${url}">Reset my password</a>
				<p>If you didn't request this email, you can safely ignore it.</p>
				<p>Thanks,</p>
				<p>${info.developerName ?? `The ${info.appName} Team`}</p>
			</div>`,
			},
			ctx,
		);
	};
}
