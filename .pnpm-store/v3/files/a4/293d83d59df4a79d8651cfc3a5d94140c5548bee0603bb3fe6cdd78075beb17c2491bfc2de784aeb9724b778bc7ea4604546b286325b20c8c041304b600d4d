import type { Meta, StoryObj } from '@storybook/react';
import { Select, SelectContent, SelectItem, SelectTrigger } from './Select.js';
import { Button } from '../button.js';

const meta = {
	title: 'Select',
	component: Select,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
	args: {
		value: 'One',
	},
} satisfies Meta<typeof Select>;

export default meta;

type Story = StoryObj<typeof Select>;

export const Default: Story = {
	render(args) {
		return (
			<Select {...args}>
				<SelectTrigger />
				<SelectContent>
					{['One', 'Two', 'Three'].map((item) => (
						<SelectItem key={item} value={item}>
							{item}
						</SelectItem>
					))}
				</SelectContent>
			</Select>
		);
	},
};

export const CompareSelectAndButton: Story = {
	render(args) {
		return (
			<div className="row">
				<Select {...args}>
					<SelectTrigger />
					<SelectContent>
						{['One', 'Two', 'Three'].map((item) => (
							<SelectItem key={item} value={item}>
								{item}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				<Button>Button</Button>

				<Select {...args}>
					<SelectTrigger size="small" />
					<SelectContent>
						{['One', 'Two', 'Three'].map((item) => (
							<SelectItem key={item} value={item}>
								{item}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				<Button size="small">Button</Button>
			</div>
		);
	},
};
