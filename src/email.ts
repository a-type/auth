import EventEmitter from 'events';
import nodemailer from 'nodemailer';

export class Email extends EventEmitter {
  private transporter;
  private user;
  private uiOrigin;
  private appName;
  private developerName;

  constructor({
    emailHost,
    emailPort = 465,
    user,
    pass,
    uiOrigin,
    appName,
    developerName = `The ${appName} Team`,
  }: {
    emailHost: string;
    emailPort?: number;
    user?: string;
    pass?: string;
    uiOrigin: string;
    appName: string;
    developerName?: string;
  }) {
    super();
    this.user = user;
    this.uiOrigin = uiOrigin;
    this.appName = appName;
    this.developerName = developerName;
    this.transporter = nodemailer.createTransport({
      host: emailHost,
      port: emailPort,
      secure: true,
      pool: true,
      auth: {
        user: user?.trim() || '',
        pass: pass?.trim() || '',
      },
    });
    this.transporter.verify().then((error) => {
      if (error !== true) {
        this.emit('error', error);
      } else {
        this.emit('ready');
      }
    });
  }

  sendEmailVerification({
    to,
    code,
    returnTo,
  }: {
    to: string;
    code: string;
    returnTo?: string;
  }) {
    return this.transporter.sendMail({
      from: this.user,
      to,
      subject: `Verify your email on ${this.appName}`,
      text: `Your verification code is ${code}`,
      html: `
			<div>
				<h1>Thanks for signing up to ${this.appName}!</h1>
				<p>Click the button below to finish signing up on this device.</p>
				<a href="${this.uiOrigin}/verify?code=${code}&email=${to}${
        returnTo ? `&returnTo=${returnTo}` : ''
      }">Verify my email</a>
				<p>After that, you can sign in on any device you want!</p>
				<p>If you didn't request this email, you can safely ignore it.</p>
				<p>Thanks,</p>
				<p>${this.developerName}</p>
			</div>`,
    });
  }

  sendPasswordReset({
    to,
    code,
    returnTo,
  }: {
    to: string;
    code: string;
    returnTo?: string;
  }) {
    return this.transporter.sendMail({
      from: this.user,
      to,
      subject: 'Reset your password on ${this.appName}',
      text: `Your password reset code is ${code}`,
      html: `
			<div>
				<h1>Reset your password on ${this.appName}</h1>
				<p>Click the link below to reset your password.</p>
				<a href="${this.uiOrigin}/reset-password?code=${code}${
        returnTo ? `&returnTo=${returnTo}` : ''
      }">Reset my password</a>
				<p>If you didn't request this email, you can safely ignore it.</p>
				<p>Thanks,</p>
				<p>${this.developerName}</p>
			</div>`,
    });
  }
}
