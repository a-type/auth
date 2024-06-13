import type { Meta, StoryObj } from '@storybook/react';
import { Tooltip } from './Tooltip.js';

const meta = {
	title: 'Tooltip',
	component: Tooltip,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
	args: {
		content: 'hello world',
	},
} satisfies Meta<typeof Tooltip>;

export default meta;

type Story = StoryObj<typeof Tooltip>;

export const Default: Story = {
	render: (args) => (
		<Tooltip {...args}>
			<button>Hover me</button>
		</Tooltip>
	),
};
