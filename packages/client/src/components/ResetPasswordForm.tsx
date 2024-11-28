import { Button, clsx, Input } from '@a-type/ui';

export interface ResetPasswordFormProps {
	code: string;
	email: string;
	endpoint: string;
	className?: string;
}

export function ResetPasswordForm({
	code,
	email,
	endpoint,
	className,
	...rest
}: ResetPasswordFormProps) {
	return (
		<form
			action={endpoint}
			method="post"
			className={clsx('flex flex-col gap-2', className)}
			{...rest}
		>
			<input type="hidden" name="code" value={code} />
			<input type="hidden" name="email" value={email} />
			<label htmlFor="newPassword">New Password</label>
			<Input
				name="newPassword"
				type="password"
				autoComplete="new-password"
				required
			/>
			<Button className="self-end" color="primary" type="submit">
				Reset password
			</Button>
		</form>
	);
}
