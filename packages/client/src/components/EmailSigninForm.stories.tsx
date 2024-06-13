import type { Meta, StoryObj } from '@storybook/react';
import { EmailSigninForm } from './EmailSigninForm.js';

const meta = {
  title: 'EmailSigninForm',
  component: EmailSigninForm,
  argTypes: {},
  parameters: {
    controls: { expanded: true },
  },
} satisfies Meta<typeof EmailSigninForm>;

export default meta;

type Story = StoryObj<typeof EmailSigninForm>;

export const Default: Story = {};
