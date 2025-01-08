import type { Meta, StoryObj } from '@storybook/react';
import { OAuthSigninButton } from './OAuthSigninButton.js';

const meta = {
  title: 'OAuthSigninButton',
  component: OAuthSigninButton,
  argTypes: {},
  args: {
    children: 'Log in with Google',
  },
  parameters: {
    controls: { expanded: true },
  },
} satisfies Meta<typeof OAuthSigninButton>;

export default meta;

type Story = StoryObj<typeof OAuthSigninButton>;

export const Default: Story = {};
