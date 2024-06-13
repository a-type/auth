import type { Meta, StoryObj } from '@storybook/react';
import { EmailSignupForm } from './EmailSignupForm.js';

const meta = {
  title: 'EmailSignupForm',
  component: EmailSignupForm,
  argTypes: {},
  parameters: {
    controls: { expanded: true },
  },
} satisfies Meta<typeof EmailSignupForm>;

export default meta;

type Story = StoryObj<typeof EmailSignupForm>;

export const Default: Story = {};
