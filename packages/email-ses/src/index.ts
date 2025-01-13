import { EmailProvider } from '@a-type/auth';
import AWS from 'aws-sdk';

export class SesEmailProvider<Context = unknown>
	implements EmailProvider<Context>
{
	private transport: AWS.SES | null = null;
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
		const transport = new AWS.SES({
			apiVersion: '2010-12-01',
			region: info.region,
			credentials: {
				accessKeyId: info.accessKeyId,
				secretAccessKey: info.secretAccessKey,
			},
		});
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
		const { transport: ses } = await this.initConnection(ctx);

		const params = {
			Destination: {
				ToAddresses: [args.to],
			},
			Message: {
				Body: {
					Html: {
						Charset: 'UTF-8',
						Data: args.html,
					},
					Text: {
						Charset: 'UTF-8',
						Data: args.text,
					},
				},
				Subject: {
					Charset: 'UTF-8',
					Data: args.subject,
				},
			},
			Source: args.from,
		};

		await ses.sendEmail(params).promise();
	};
}
