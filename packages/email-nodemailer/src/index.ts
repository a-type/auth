import { EmailProvider } from '@a-type/auth';
import nodemailer from 'nodemailer';

export class NodemailerEmailProvider<Context = unknown>
	implements EmailProvider<Context>
{
	private transport: nodemailer.Transporter | null = null;
	private getConnectionInfo;

	constructor({
		getConnectionInfo,
	}: {
		getConnectionInfo(ctx: Context): Promise<{
			user: string;
			pass: string;
			emailHost: string;
			emailPort?: string;
		}>;
	}) {
		this.getConnectionInfo = getConnectionInfo;
	}

	private async initConnection(ctx: Context) {
		if (this.transport) {
			return {
				transport: this.transport,
			};
		}
		const info = await this.getConnectionInfo(ctx);
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
			transport: this.transport,
		};
	}

	sendMail = async (
		args: {
			from: string;
			to: string;
			subject: string;
			text: string;
			html: string;
		},
		ctx: Context,
	) => {
		const { transport } = await this.initConnection(ctx);
		return transport.sendMail(args);
	};
}
