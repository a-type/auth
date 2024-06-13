import classNames, { clsx } from 'clsx';
import { withClassName } from '../../hooks.js';
import { ReactNode, forwardRef } from 'react';
import { Slot } from '@radix-ui/react-slot';
import { Icon, IconProps } from '../icon.js';

export const navBarItemClass = classNames(
	'layer-components:(flex flex-col items-center justify-center whitespace-nowrap py-1 px-3 bg-transparent rounded-md border-none cursor-pointer text-sm transition-colors h-full gap-6px relative text-gray-7 select-none)',
	'layer-components:sm:(flex-row-reverse h-auto justify-start gap-2 overflow-visible)',
	'layer-components:hover:bg-primary-wash',
	'layer-components:focus-visible:(outline-none bg-primary-wash)',
	'layer-components:active:bg-primary-wash layer-components:sm:active:bg-gray-dark-blend',
	'layer-components:[&[data-active=true]]:(bg-primary-wash text-primary-dark)',
);

export interface NavBarItemProps {
	asChild?: boolean;
	className?: string;
	children?: ReactNode;
	active?: boolean;
}

export const NavBarItem = forwardRef<HTMLDivElement, NavBarItemProps>(
	function NavBarItem({ asChild, className, active, ...rest }, ref) {
		const Comp = asChild ? Slot : 'div';

		return (
			<Comp
				ref={ref}
				className={classNames(navBarItemClass, className)}
				data-active={active}
				{...rest}
			/>
		);
	},
);

export const NavBarItemIconWrapper = withClassName(
	'div',
	'layer-components:(relative flex) layer-components:sm:(p-6px rounded-full bg-gray-blend)',
	'layer-variants:sm:[*[data-active=true]_&]:bg-primary-light',
);

export const NavBarItemText = withClassName(
	'span',
	'layer-components:(overflow-hidden pl-1 inline-block text-xxs whitespace-nowrap text-ellipsis) layer-components:sm:(text-md leading-normal)',
);

interface NavBarItemIconProps {
	asChild?: boolean;
	name?: IconProps['name'];
	className?: string;
	children?: ReactNode;
}
export const NavBarItemIcon = forwardRef<any, NavBarItemIconProps>(
	function NavBarItemIcon(
		{ children, asChild, className, name = 'placeholder', ...rest },
		ref,
	) {
		const Comp = asChild ? Slot : Icon;
		return (
			<Comp
				name={name}
				className={clsx(
					'layer-components:(relative z-1 flex fill-none)',
					'layer-variants:[*[data-active=true]_&]:fill-primary-light',
					className,
				)}
				{...rest}
				ref={ref}
			>
				{children}
			</Comp>
		);
	},
);

export const NavBarItemPip = withClassName(
	'div',
	'layer-components:(absolute top-6px right-6px w-6px h-6px rounded-full bg-attention shadow-sm)',
);

export const NavBarRoot = withClassName(
	'div',
	'layer-components:(grid [grid-auto-columns:1fr] [grid-auto-flow:column] justify-items-center w-full rounded-0 overflow-hidden z-50 p-1 h-auto)',
	'pb-[calc(0.25rem+env(safe-area-inset-bottom,0px))]',
	'layer-components:sm:(bg-transparent flex flex-col rounded-0 border-none border-transparent shadow-none h-min-content overflow-y-auto overflow-x-hidden justify-start items-stretch gap-2 pb-10)',
);
