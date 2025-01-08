import type { Meta, StoryObj } from '@storybook/react';
import { EmailCompleteSignupForm } from './EmailCompleteSignupForm.js';

const meta = {
  title: 'EmailCompleteSignupForm',
  component: EmailCompleteSignupForm,
  argTypes: {},
  parameters: {
    controls: { expanded: true },
  },
} satisfies Meta<typeof EmailCompleteSignupForm>;

export default meta;

type Story = StoryObj<typeof EmailCompleteSignupForm>;

export const Default: Story = {};
