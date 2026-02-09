// @unocss-include
import { Button, clsx, Input } from '@a-type/ui';

export interface EmailCompleteSignUpFormProps {
	code: string;
	email: string;
	endpoint: string;
	className?: string;
}

export function EmailCompleteSignupForm({
	code,
	email,
	endpoint,
	className,
	...rest
}: EmailCompleteSignUpFormProps) {
	return (
		<form
			action={endpoint}
			method="post"
			className={clsx('flex flex-col gap-2', className)}
			{...rest}
		>
			<input type="hidden" name="code" value={code} />
			<input type="hidden" name="email" value={email} />
			<label htmlFor="password" className="w-full">
				Password
			</label>
			<Input
				name="password"
				type="password"
				autoComplete="new-password"
				required
				className="w-full"
			/>
			<Button className="self-end" emphasis="primary" type="submit">
				Sign In
			</Button>
		</form>
	);
}
