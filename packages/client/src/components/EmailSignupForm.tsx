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
}

export function EmailSignupForm({
  returnTo,
  actionText = 'Start signup',
  disabled,
  endpoint,
}: EmailSignupFormProps) {
  const [success, setSuccess] = useState(false);

  if (success) {
    return (
      <div className="flex flex-col gap-2">
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
          const response = await fetch(endpoint, {
            method: 'post',
            body: formData,
          });
          if (response.ok) {
            setSuccess(true);
          }
        } catch (e) {
          console.error(e);
        }
      }}
      className="flex flex-col gap-2"
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
