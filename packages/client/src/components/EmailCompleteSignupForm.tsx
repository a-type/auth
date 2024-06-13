import { Input } from '@a-type/ui/components/input';
import { Button } from '@a-type/ui/components/button';

export interface EmailCompleteSignUpFormProps {
  code: string;
  email: string;
  emailSignupEndpoint: string;
}

export function EmailCompleteSignupForm({
  code,
  email,
  emailSignupEndpoint,
}: EmailCompleteSignUpFormProps) {
  return (
    <form
      action={emailSignupEndpoint}
      method="post"
      className="flex flex-col gap-2"
    >
      <input type="hidden" name="code" value={code} />
      <input type="hidden" name="email" value={email} />
      <label htmlFor="password">Password</label>
      <Input
        name="password"
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
