import type { Meta, StoryObj } from '@storybook/react';
import {
	CameraDeviceSelector,
	CameraRoot,
	CameraShutterButton,
} from './Camera.js';
import { useMemo, useState } from 'react';

const meta = {
	title: 'Camera',
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
	args: {},
} satisfies Meta;

export default meta;

type Story = StoryObj;

export const Default: Story = {
	render() {
		return <CameraDemo />;
	},
};

export const BackCamera: Story = {
	render() {
		return <CameraDemo facingMode="environment" />;
	},
};

function CameraDemo({ facingMode }: { facingMode?: 'user' | 'environment' }) {
	const [latest, setLatest] = useState<File | undefined>();
	const dataUri = useMemo(
		() => (latest ? URL.createObjectURL(latest) : undefined),
		[latest],
	);

	return (
		<div>
			<CameraRoot
				facingMode={facingMode}
				onCapture={setLatest}
				className="w-64 h-64"
			>
				<CameraShutterButton />
				<CameraDeviceSelector />
			</CameraRoot>
			{latest && <img src={dataUri} className="w-full" />}
		</div>
	);
}
