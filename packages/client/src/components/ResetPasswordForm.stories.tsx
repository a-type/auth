import type { Meta, StoryObj } from '@storybook/react';
import { ResetPasswordForm } from './ResetPasswordForm.js';

const meta = {
  title: 'ResetPasswordForm',
  component: ResetPasswordForm,
  argTypes: {},
  parameters: {
    controls: { expanded: true },
  },
} satisfies Meta<typeof ResetPasswordForm>;

export default meta;

type Story = StoryObj<typeof ResetPasswordForm>;

export const Default: Story = {};
