import { MouseEvent, ReactNode, forwardRef } from 'react';
import { withClassName } from '../../hooks.js';
import { Slot } from '@radix-ui/react-slot';
import classNames from 'clsx';

export const CardRoot = withClassName(
	'div',
	'layer-components:(flex flex-col border-light rounded-lg text-lg overflow-hidden h-max-content relative bg-gray-1 text-black shadow-sm)',
);

export const CardMain = forwardRef<
	any,
	{
		asChild?: boolean;
		className?: string;
		onClick?: (ev: MouseEvent) => void;
		children?: ReactNode;
		compact?: boolean;
		/** forces non-interactive version */
		nonInteractive?: boolean;
	}
>(function CardMain(
	{ asChild, className, compact, nonInteractive, ...rest },
	ref,
) {
	const isInteractive = !nonInteractive && (!!asChild || !!rest.onClick);
	const Comp = asChild ? Slot : isInteractive ? 'button' : 'div';
	return (
		<Comp
			ref={ref}
			className={classNames(
				'layer-components:(flex flex-col gap-1 transition p-4 pb-2 flex-1 relative z-1 bg-transparent border-none text-start text-inherit text-sm)',
				'layer-components:md:pt-4',
				compact && 'layer-variants:(p-1 bg-white gap-0)',
				isInteractive &&
					'layer-components:cursor-pointer layer-components:hover:(bg-gray-blend color-black) layer-components:focus:outline-none layer-components:focus-visible:(outline-none ring-inset ring-4 ring-gray-5)',
				className,
			)}
			data-compact={compact}
			{...rest}
		/>
	);
});

export const CardTitle = withClassName(
	'div',
	'layer-components:(flex flex-col gap-1 mt-auto bg-white p-2 rounded-lg w-auto mr-auto border border-solid border-grayDarkBlend text-md max-h-80px overflow-hidden text-ellipsis max-w-full text-inherit)',
	'[data-compact=true]>&:(bg-transparent border-none p-2 whitespace-nowrap text-ellipsis overflow-hidden)',
);

export const CardContent = withClassName(
	'div',
	'layer-components:(flex flex-col gap-1 p-2)',
);

export const CardImage = withClassName(
	'div',
	'layer-components:(absolute z-0 right-0 top-0 bottom-0 w-full h-full)',
);

export const CardFooter = withClassName(
	'div',
	'layer-components:(flex flex-row p-2 bg-white relative z-1 border-0 border-t border-t-grayDarkBlend border-solid)',
);

export const CardActions = withClassName(
	'div',
	'layer-components:(ml-0 mr-auto flex flex-row gap-1 items-center)',
);

export const CardMenu = withClassName(
	'div',
	'layer-components:(mr-0 ml-auto flex flex-row gap-1 items-center)',
);

export const CardGrid = withClassName(
	'div',
	'layer-components:(grid grid-cols-[1fr] [grid-auto-rows:auto] gap-4 p-0 m-0)',
	'layer-components:md:(grid-cols-[repeat(2,1fr)] [grid-auto-rows:1fr] items-end)',
);
