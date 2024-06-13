import { Input } from '@a-type/ui/components/input';
import { Button } from '@a-type/ui/components/button';

export interface ResetPasswordFormProps {
  code: string;
  email: string;
  resetPasswordEndpoint: string;
}

export function ResetPasswordForm({
  code,
  email,
  resetPasswordEndpoint,
}: ResetPasswordFormProps) {
  return (
    <form
      action={resetPasswordEndpoint}
      method="post"
      className="flex flex-col gap-2"
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
        Sign In
      </Button>
    </form>
  );
}
