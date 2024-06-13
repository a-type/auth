import classNames from 'clsx';
import { forwardRef, ReactNode } from 'react';

export const PageRoot = forwardRef<
	HTMLDivElement,
	{
		children?: ReactNode;
		className?: string;
	}
>(function PageRoot({ className, children, ...props }, ref) {
	return (
		<div
			ref={ref}
			className={classNames(
				'layer-components:(flex-grow-1 flex-shrink-1 flex-basis-0 min-h-0 h-full bg-gray-1)',
				'layer-components:(grid grid-areas-[content]-[nav] grid-cols-[1fr] grid-rows-[1fr] items-start justify-center)',
				'sm:layer-responsive:(grid-areas-[gutter1_nav_content_gutter2] grid-cols-[1fr_auto_min(800px,60vw)_1fr] min-h-auto bg-wash)',
				className,
			)}
			{...props}
		>
			{children}
		</div>
	);
});
