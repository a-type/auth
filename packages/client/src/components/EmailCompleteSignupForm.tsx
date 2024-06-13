import { Input } from '@a-type/ui/components/input';
import { Button } from '@a-type/ui/components/button';

export interface EmailCompleteSignUpFormProps {
  code: string;
  email: string;
  endpoint: string;
}

export function EmailCompleteSignupForm({
  code,
  email,
  endpoint,
}: EmailCompleteSignUpFormProps) {
  return (
    <form action={endpoint} method="post" className="flex flex-col gap-2">
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
