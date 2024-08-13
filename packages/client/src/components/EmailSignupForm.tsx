import { clsx } from '@a-type/ui';
import {
  FormikForm,
  SubmitButton,
  TextField,
} from '@a-type/ui/components/forms';
import { useState } from 'react';

export interface EmailSignupFormProps {
  returnTo?: string | null;
  actionText?: string;
  disabled?: boolean;
  endpoint: string;
  className?: string;
  appState?: any;
  onError?: (error: Error) => void;
}

export function EmailSignupForm({
  returnTo,
  actionText = 'Verify email',
  disabled,
  endpoint,
  className,
  appState,
  onError,
  ...rest
}: EmailSignupFormProps) {
  const [success, setSuccess] = useState(false);

  if (success) {
    return (
      <div className={clsx('flex flex-col gap-2', className)} {...rest}>
        <p className="text-lg">Check your email for a verification code.</p>
      </div>
    );
  }

  return (
    <FormikForm
      initialValues={{
        name: '',
        email: '',
      }}
      onSubmit={async (values, helpers) => {
        if (disabled) return;
        try {
          // this API accepts form data
          const formData = new FormData();
          formData.append('name', values.name);
          formData.append('email', values.email);
          formData.append('returnTo', returnTo ?? '');
          if (appState) {
            formData.append('appState', JSON.stringify(appState));
          }
          const response = await fetch(endpoint, {
            method: 'post',
            body: formData,
          });
          if (response.ok) {
            setSuccess(true);
          }
        } catch (e) {
          onError?.(e as Error);
        }
      }}
      className={clsx('flex flex-col gap-2', className)}
      {...rest}
    >
      <TextField name="name" label="Name" autoComplete="given-name" required />
      <TextField
        name="email"
        type="email"
        label="Email"
        autoComplete="email"
        required
      />
      <SubmitButton
        disabled={disabled}
        type="submit"
        className="self-end"
        color="primary"
      >
        {actionText}
      </SubmitButton>
    </FormikForm>
  );
}
