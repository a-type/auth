import type { Meta, StoryObj } from '@storybook/react';
import { TabsRoot, TabsList, TabsContent, TabsTrigger } from './tabs.js';

const meta = {
	title: 'Tabs',
	argTypes: {},
	parameters: {
		controls: { expanded: true },
	},
} satisfies Meta;

export default meta;

type Story = StoryObj;

export const Default: Story = {
	render: () => (
		<TabsRoot>
			<TabsList>
				<TabsTrigger value="tab1">Tab 1</TabsTrigger>
				<TabsTrigger value="tab2">Tab 2</TabsTrigger>
				<TabsTrigger value="tab3">Tab 3</TabsTrigger>
			</TabsList>
			<TabsContent value="tab1">
				<div>Tab 1 content</div>
			</TabsContent>
			<TabsContent value="tab2">
				<div>Tab 2 content</div>
			</TabsContent>
			<TabsContent value="tab3">
				<div>Tab 3 content</div>
			</TabsContent>
		</TabsRoot>
	),
} satisfies Story;
