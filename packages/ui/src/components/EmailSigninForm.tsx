import {
	Button,
	clsx,
	Dialog,
	DialogActions,
	DialogClose,
	DialogContent,
	DialogTrigger,
	FormikForm,
	Input,
	TextField,
	toast,
} from '@a-type/ui';
import { useState } from 'react';

export interface EmailSigninFormProps {
	returnTo?: string;
	endpoint: string;
	resetPasswordEndpoint: string;
	className?: string;
	appState?: any;
}

export function EmailSigninForm({
	returnTo = '',
	endpoint,
	resetPasswordEndpoint,
	className,
	appState,
	...rest
}: EmailSigninFormProps) {
	const url = new URL(endpoint);
	if (returnTo) {
		url.searchParams.append('returnTo', returnTo);
	}
	if (appState) {
		url.searchParams.append('appState', JSON.stringify(appState));
	}

	return (
		<form
			className={clsx('flex flex-col gap-2 items-stretch', className)}
			method="post"
			action={url.toString()}
			{...rest}
		>
			<label htmlFor="email" className="font-bold w-full">
				Email
			</label>
			<Input name="email" autoComplete="email" required className="w-full" />
			<label htmlFor="password" className="font-bold w-full">
				Password
			</label>
			<Input
				autoComplete="current-password"
				name="password"
				type="password"
				required
				className="w-full"
			/>
			<input type="hidden" name="csrfToken" value={appState?.csrfToken || ''} />
			<input type="hidden" name="returnTo" value={returnTo} />
			<input type="hidden" name="appState" value={JSON.stringify(appState)} />
			<Button type="submit" className="self-end" emphasis="primary">
				Sign In
			</Button>
			<ForgotPassword className="self-end" endpoint={resetPasswordEndpoint} />
		</form>
	);
}

function ForgotPassword({
	className,
	endpoint,
}: {
	className?: string;
	endpoint: string;
}) {
	const [open, setOpen] = useState(false);
	const [errorMessage, setErrorMessage] = useState('');
	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogTrigger
				className={className}
				render={
					<button className="bg-transparent border-none p-0 color-black underline cursor-pointer" />
				}
			>
				Forgot password?
			</DialogTrigger>
			<DialogContent>
				<FormikForm
					className="flex flex-col gap-2 w-full"
					initialValues={{
						email: '',
					}}
					onSubmit={async (values, _helpers) => {
						try {
							const formData = new FormData();
							formData.append('email', values.email);
							let returnTo = window.location.pathname;
							if (window.location.search) {
								returnTo += window.location.search;
							}
							formData.append('returnTo', returnTo);
							const response = await fetch(endpoint, {
								method: 'post',
								body: formData,
							});
							if (response.ok) {
								setOpen(false);
								toast.success('Reset email sent. Check your inbox.');
							} else {
								setErrorMessage('Failed to send reset email. Try again?');
							}
						} catch (err) {
							console.error(err);
							setErrorMessage('Failed to send reset email. Try again?');
						}
					}}
				>
					<TextField label="Email" name="email" type="email" required />
					{errorMessage && (
						<p className="text-attention-dark py-3">{errorMessage}</p>
					)}
					<DialogActions>
						<DialogClose>Cancel</DialogClose>
						<Button color="primary" type="submit" className="self-end">
							Send reset email
						</Button>
					</DialogActions>
				</FormikForm>
			</DialogContent>
		</Dialog>
	);
}
