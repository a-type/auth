import type { Meta, StoryObj } from '@storybook/react';
import {
	Dialog,
	DialogContent,
	DialogTrigger,
	DialogActions,
	DialogClose,
	DialogTitle,
} from './Dialog.js';
import { ParticleLayer } from '../particles.js';

const meta = {
	title: 'Dialog',
	component: Dialog,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
} satisfies Meta<typeof Dialog>;

export default meta;

type Story = StoryObj<typeof Dialog>;

export const Default: Story = {
	args: {
		children: (
			<ParticleLayer noPortal>
				<DialogTrigger>Open</DialogTrigger>
				<DialogContent>
					<DialogTitle>Hello world</DialogTitle>
					<DialogActions>
						<DialogClose>Close</DialogClose>
					</DialogActions>
				</DialogContent>
			</ParticleLayer>
		),
	},
};

export const NoSheet: Story = {
	args: {
		children: (
			<ParticleLayer noPortal>
				<DialogTrigger>Open</DialogTrigger>
				<DialogContent disableSheet>
					<DialogTitle>Hello world</DialogTitle>
					<DialogActions>
						<DialogClose>Close</DialogClose>
					</DialogActions>
				</DialogContent>
			</ParticleLayer>
		),
	},
};

export const Positioned: Story = {
	args: {
		children: (
			<ParticleLayer noPortal>
				<DialogTrigger>Open</DialogTrigger>
				<DialogContent className="top-auto bottom-0px">
					<DialogTitle>Hello world</DialogTitle>
					<DialogActions>
						<DialogClose>Close</DialogClose>
					</DialogActions>
				</DialogContent>
			</ParticleLayer>
		),
	},
};
