import type { Meta, StoryObj } from '@storybook/react';
import { DatePicker, DateRangePicker } from './DatePicker.js';
import { useState } from 'react';

const meta = {
	title: 'DatePicker',
	component: DatePicker,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
} satisfies Meta<typeof DatePicker>;

export default meta;

type Story = StoryObj<typeof DatePicker>;

export const Default: Story = {
	render() {
		const [value, setValue] = useState<Date | null>(null);
		return <DatePicker value={value} onChange={setValue} />;
	},
};

export const Range: Story = {
	render() {
		const [value, setValue] = useState<{
			start: Date | null;
			end: Date | null;
		}>({ start: null, end: null });
		return <DateRangePicker value={value} onChange={setValue} />;
	},
};
