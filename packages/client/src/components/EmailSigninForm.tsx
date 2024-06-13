import { clsx } from '@a-type/ui';
import { Button } from '@a-type/ui/components/button';
import {
  Dialog,
  DialogActions,
  DialogClose,
  DialogContent,
  DialogTrigger,
} from '@a-type/ui/components/dialog';
import { FormikForm, TextField } from '@a-type/ui/components/forms';
import { Input } from '@a-type/ui/components/input';
import { useState } from 'react';

export interface EmailSigninFormProps {
  returnTo?: string;
  endpoint: string;
  resetPasswordEndpoint: string;
  className?: string;
}

export function EmailSigninForm({
  returnTo = '',
  endpoint,
  resetPasswordEndpoint,
  className,
  ...rest
}: EmailSigninFormProps) {
  return (
    <form
      className={clsx('flex flex-col gap-2', className)}
      method="post"
      action={`${endpoint}?returnTo=${returnTo}`}
      {...rest}
    >
      <label htmlFor="email" className="font-bold">
        Email
      </label>
      <Input name="email" autoComplete="email" required />
      <label htmlFor="password" className="font-bold">
        Password
      </label>
      <Input
        autoComplete="current-password"
        name="password"
        type="password"
        required
      />
      <Button type="submit" className="self-end" color="primary">
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
      <DialogTrigger asChild className={className}>
        <button className="bg-transparent border-none p-0 color-black underline cursor-pointer">
          Forgot password?
        </button>
      </DialogTrigger>
      <DialogContent>
        <FormikForm
          className="flex flex-col gap-2 w-full"
          initialValues={{
            email: '',
          }}
          onSubmit={async (values, helpers) => {
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
            <DialogClose asChild>
              <Button>Cancel</Button>
            </DialogClose>
            <Button color="primary" type="submit" className="self-end">
              Send reset email
            </Button>
          </DialogActions>
        </FormikForm>
      </DialogContent>
    </Dialog>
  );
}
