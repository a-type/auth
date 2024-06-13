import type { Meta, StoryObj } from '@storybook/react';
import {
	CardActions,
	CardContent,
	CardFooter,
	CardMain,
	CardRoot,
	CardTitle,
} from './Card.js';
import { Button } from '../button.js';
import { Icon } from '../icon.js';

const meta = {
	title: 'Card',
	component: CardRoot,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
} satisfies Meta<typeof CardRoot>;

export default meta;

type Story = StoryObj<typeof CardRoot>;

export const Default: Story = {
	render: () => (
		<CardRoot>
			<CardMain onClick={() => alert('clicked')}>
				<CardTitle>Card Title</CardTitle>
				<CardContent>Other stuff</CardContent>
			</CardMain>
			<CardFooter>
				<CardActions>
					<Button size="small">Button</Button>
					<Button size="icon" color="ghost">
						<Icon name="placeholder" />
					</Button>
				</CardActions>
			</CardFooter>
		</CardRoot>
	),
};

export const Compact: Story = {
	render: () => (
		<CardRoot>
			<CardMain compact>
				<CardTitle>Card Title</CardTitle>
			</CardMain>
			<CardFooter>
				<CardActions>
					<Button size="small">Button</Button>
					<Button size="icon" color="ghost">
						<Icon name="placeholder" />
					</Button>
				</CardActions>
			</CardFooter>
		</CardRoot>
	),
};

export const NonInteractive: Story = {
	render: () => (
		<CardRoot>
			<CardMain>
				<CardTitle>Card Title</CardTitle>
				<CardContent>Other stuff</CardContent>
			</CardMain>
			<CardFooter>
				<CardActions>
					<Button size="small">Button</Button>
					<Button size="icon" color="ghost">
						<Icon name="placeholder" />
					</Button>
				</CardActions>
			</CardFooter>
		</CardRoot>
	),
};

export const AsChild: Story = {
	render: () => (
		<CardRoot>
			<CardMain asChild>
				<a href="#here">
					<CardTitle>Card Title</CardTitle>
					<CardContent>Other stuff</CardContent>
				</a>
			</CardMain>
			<CardFooter>
				<CardActions>
					<Button size="small">Button</Button>
					<Button size="icon" color="ghost">
						<Icon name="placeholder" />
					</Button>
				</CardActions>
			</CardFooter>
		</CardRoot>
	),
};

export const AsChildNonInteractive: Story = {
	render: () => (
		<CardRoot>
			<CardMain asChild nonInteractive>
				<button>
					<CardTitle>Card Title</CardTitle>
					<CardContent>Other stuff</CardContent>
				</button>
			</CardMain>
			<CardFooter>
				<CardActions>
					<Button size="small">Button</Button>
					<Button size="icon" color="ghost">
						<Icon name="placeholder" />
					</Button>
				</CardActions>
			</CardFooter>
		</CardRoot>
	),
};
