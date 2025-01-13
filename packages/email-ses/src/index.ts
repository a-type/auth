import { EmailProvider } from '@a-type/auth';
import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';

export class SesEmailProvider<Context = unknown>
	implements EmailProvider<Context>
{
	private transport: SESv2Client | null = null;
	private getConnectionInfo;
	constructor({
		getConnectionInfo,
	}: {
		getConnectionInfo(ctx: Context): Promise<{
			accessKeyId: string;
			secretAccessKey: string;
			region?: string;
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
		return {
			transport: new SESv2Client({
				region: info.region,
				credentials: {
					accessKeyId: info.accessKeyId,
					secretAccessKey: info.secretAccessKey,
				},
			}),
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
		const { transport: ses } = await this.initConnection(ctx);

		const { from, to, subject, text, html } = args;
		const command = new SendEmailCommand({
			Content: {
				Simple: {
					Body: {
						Html: {
							Data: html,
						},
						Text: {
							Data: text,
						},
					},
					Subject: {
						Data: subject,
					},
				},
			},
			Destination: {
				ToAddresses: [to],
			},
			FromEmailAddress: from,
		});
		await ses.send(command);
	};
}
