import type { Meta, StoryObj } from '@storybook/react';
import { PageRoot } from './PageRoot.js';
import { PageContent } from './PageContent.js';
import { PageNav } from './PageNav.js';
import {
	NavBarItem,
	NavBarItemIcon,
	NavBarItemIconWrapper,
	NavBarItemPip,
	NavBarItemText,
	NavBarRoot,
} from '../navBar.js';
import { Icon } from '../icon.js';

const meta = {
	title: 'layouts',
	argTypes: {},
	parameters: {
		controls: { expanded: true },
		layout: 'fullscreen',
	},
} satisfies Meta;

export default meta;

type Story = StoryObj;

export const Default: Story = {
	render: () => (
		<PageRoot className="w-full h-full">
			<PageContent>
				<div className="text-center">
					<h1 className="text-3xl font-bold">Hello, World!</h1>
					<p className="text-lg">This is a simple page layout.</p>
				</div>
			</PageContent>
			<PageNav>
				<NavBarRoot>
					<NavBarItem>
						<NavBarItemIconWrapper>
							<NavBarItemIcon name="cart" />
						</NavBarItemIconWrapper>
						<NavBarItemText>Item 1 long</NavBarItemText>
					</NavBarItem>
					<NavBarItem active={true}>
						<NavBarItemIconWrapper>
							<NavBarItemIcon asChild>
								<Icon name="book" />
							</NavBarItemIcon>
						</NavBarItemIconWrapper>
						<NavBarItemText>Item 2</NavBarItemText>
						<NavBarItemPip />
					</NavBarItem>
				</NavBarRoot>
			</PageNav>
		</PageRoot>
	),
};
