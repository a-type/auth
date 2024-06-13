import type { Meta, StoryObj } from '@storybook/react';
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuItemRightSlot,
	DropdownMenuTrigger,
} from './DropdownMenu.js';
import { Icon } from '../icon.js';
import { DropdownMenuLabel } from '@radix-ui/react-dropdown-menu';

const meta = {
	title: 'DropdownMenu',
	component: DropdownMenu,
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
} satisfies Meta<typeof DropdownMenu>;

export default meta;

type Story = StoryObj<typeof DropdownMenu>;

export const Default: Story = {
	args: {
		children: (
			<>
				<DropdownMenuTrigger>Open</DropdownMenuTrigger>
				<DropdownMenuContent>
					<DropdownMenuItem color="destructive">
						<DropdownMenuLabel>Item 1</DropdownMenuLabel>
						<DropdownMenuItemRightSlot>
							<Icon name="flag" />
						</DropdownMenuItemRightSlot>
					</DropdownMenuItem>
					<DropdownMenuItem>
						<DropdownMenuLabel>Item 2</DropdownMenuLabel>
						<DropdownMenuItemRightSlot>
							<Icon name="add_person" />
						</DropdownMenuItemRightSlot>
					</DropdownMenuItem>
				</DropdownMenuContent>
			</>
		),
	},
};
