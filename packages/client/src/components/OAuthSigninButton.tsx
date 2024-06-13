import { Button, ButtonProps } from '@a-type/ui/components/button';
import { ReactNode } from 'react';

export function OAuthSigninButton({
  returnTo,
  children,
  className,
  inviteId,
  oAuthSignInEndpoint,
  ...rest
}: {
  returnTo?: string | null;
  children?: ReactNode;
  inviteId?: string | null;
  oAuthSignInEndpoint: string;
} & ButtonProps) {
  const url = new URL(oAuthSignInEndpoint ?? window.location.origin);
  if (returnTo) {
    url.searchParams.set('returnTo', returnTo);
  }
  if (inviteId) {
    url.searchParams.set('inviteId', inviteId);
  }

  return (
    <form action={url.toString()} className={className} method="post">
      <Button type="submit" {...rest}>
        {children}
      </Button>
    </form>
  );
}
