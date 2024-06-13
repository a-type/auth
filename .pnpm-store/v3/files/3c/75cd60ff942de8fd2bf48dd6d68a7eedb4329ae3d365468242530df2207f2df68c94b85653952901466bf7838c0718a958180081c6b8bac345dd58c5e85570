'use client';

import { ComponentPropsWithoutRef } from 'react';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import classNames from 'clsx';

function Content({
	children,
	className,
	...props
}: TooltipPrimitive.TooltipContentProps) {
	return (
		<TooltipPrimitive.Portal>
			<TooltipPrimitive.Content
				className={classNames(
					'layer-components:(relative rounded-md py-2 px-3 bg-black text-white text-sm leading-tight shadow-sm select-none hidden z-tooltip sm:display-initial)',
					'[&[data-state=delayed-open]]:display-initial',
					'[&[data-state=instant-open]]:display-initial',
					'layer-components:transform-origin-[var(--radix-tooltip-content-transform-origin)]',
					'layer-components:[&[data-state=delayed-open]]:animate-popover-in',
					className,
				)}
				{...props}
			>
				{children}
				<TooltipPrimitive.Arrow className="fill-black" />
			</TooltipPrimitive.Content>
		</TooltipPrimitive.Portal>
	);
}

export const TooltipProvider = TooltipPrimitive.Provider;

export function Tooltip({
	content,
	children,
	open,
	disabled,
	...rest
}: { content: React.ReactNode; open?: boolean } & ComponentPropsWithoutRef<
	typeof TooltipPrimitive.TooltipTrigger
>) {
	return (
		<TooltipPrimitive.Root open={open}>
			{disabled ? (
				children
			) : (
				<TooltipPrimitive.TooltipTrigger asChild {...rest}>
					{children}
				</TooltipPrimitive.TooltipTrigger>
			)}
			<Content sideOffset={12}>{content}</Content>
		</TooltipPrimitive.Root>
	);
}
