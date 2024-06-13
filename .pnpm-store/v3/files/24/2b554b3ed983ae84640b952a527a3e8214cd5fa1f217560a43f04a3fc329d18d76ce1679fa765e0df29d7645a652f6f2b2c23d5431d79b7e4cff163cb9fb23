import type { Meta, StoryObj } from '@storybook/react';
import { ImageUploader } from './ImageUploader.js';
import { useState } from 'react';

const meta = {
	title: 'ImageUploader',
	component: ImageUploader,
	argTypes: {
		onChange: { action: 'change' },
	},
	parameters: {
		controls: { expanded: true },
	},
	args: {
		className: 'w-64 h-64',
	},
} satisfies Meta<typeof ImageUploader>;

export default meta;

type Story = StoryObj<typeof ImageUploader>;

export const Default: Story = {
	render: () => <ImageUploaderDemo />,
};

function ImageUploaderDemo() {
	const [value, setValue] = useState<string | null>(null);

	return (
		<ImageUploader
			onChange={(file) =>
				file ? setValue(URL.createObjectURL(file)) : setValue(null)
			}
			value={value}
			className="w-64 h-64"
		/>
	);
}
