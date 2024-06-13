import * as Tabs from '@radix-ui/react-tabs';
import { withClassName } from '../../hooks/withClassName.js';

export const TabsRoot = withClassName(Tabs.Root, '');

export const TabsList = withClassName(
	Tabs.List,
	'flex flex-row py-2 px-2 justify-center items-start gap-2',
);

export const TabsTrigger = withClassName(
	Tabs.Trigger,
	'flex flex-row items-center justify-center gap-2 color-black py-1 px-4 bg-wash text-md min-w-100px rounded-full border border-1 border-primary border-solid transition-colors cursor-pointer select-none',
	'hover:bg-primary-light focus-visible:(focus-ring focus-ring-primary-dark outline-off bg-primary-light border-primary-dark) [&[data-state=active]]:(font-bold bg-primary-light border-primary-light text-black cursor-default hover:bg-primary-light relative z-1)',
);

export const TabsContent = withClassName(Tabs.Content, '');
