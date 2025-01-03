import EventEmitter from 'events';
import nodemailer from 'nodemailer';

export class Email<Context = unknown> extends EventEmitter {
	private transport: nodemailer.Transporter | null = null;
	private getConnectionInfo;

	constructor({
		getConnectionInfo,
	}: {
		getConnectionInfo(
			ctx: Context,
		): Promise<{
			user: string;
			pass: string;
			uiOrigin: string;
			emailHost: string;
			emailPort?: string;
			appName: string;
			developerName?: string;
		}>;
	}) {
		super();
		this.getConnectionInfo = getConnectionInfo;
	}

	private async initConnection(ctx: Context) {
		const info = await this.getConnectionInfo(ctx);
		if (this.transport) {
			return {
				info: {
					developerName: info.developerName ?? `The ${info.appName} team`,
					...info,
				},
				transport: this.transport,
			};
		}
		const transport = nodemailer.createTransport({
			host: info.emailHost,
			port: info.emailPort || 465,
			secure: true,
			pool: true,
			auth: {
				user: info.user.trim(),
				pass: info.pass.trim(),
			},
		} as any);
		await transport.verify();
		this.transport = transport;
		return {
			info: {
				developerName: info.developerName ?? `The ${info.appName} team`,
				...info,
			},
			transport: this.transport,
		};
	}

	sendMail = async (
		args: { to: string; subject: string; text: string; html: string },
		ctx: Context,
	) => {
		const { transport, info } = await this.initConnection(ctx);
		return transport.sendMail({ from: info.user, ...args });
	};

	sendEmailVerification = async (
		{ to, code }: { to: string; code: string },
		ctx: Context,
	) => {
		const { info, transport } = await this.initConnection(ctx);
		const url = new URL('/verify', info.uiOrigin);
		url.searchParams.set('code', code);
		url.searchParams.set('email', to);
		return transport.sendMail({
			from: info.user,
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
				<p>${info.developerName}</p>
			</div>`,
		});
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
		const { transport, info } = await this.initConnection(ctx);
		const url = new URL('/reset-password', info.uiOrigin);
		url.searchParams.set('code', code);
		url.searchParams.set('email', to);
		if (returnTo) {
			url.searchParams.set('returnTo', returnTo);
		}
		if (appState) {
			url.searchParams.set('appState', appState);
		}

		return transport.sendMail({
			from: info.user,
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
				<p>${info.developerName}</p>
			</div>`,
		});
	};
}
