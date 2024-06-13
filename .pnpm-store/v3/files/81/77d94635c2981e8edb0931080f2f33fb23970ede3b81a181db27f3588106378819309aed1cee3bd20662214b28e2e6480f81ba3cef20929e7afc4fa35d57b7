'use client';

import classNames from 'clsx';
import { HTMLAttributes } from 'react';

export function PageNav({
	className,
	children,
	...props
}: HTMLAttributes<HTMLDivElement>) {
	return (
		<div
			{...props}
			className={classNames(
				'layer-components:([grid-area:nav] relative z-nav pb-[calc(0.25rem+env(safe-area-inset-bottom,0px))])',
				'layer-components:sm:([grid-area:nav] sticky top-0 h-auto bottom-auto left-auto right-auto)',
				className,
			)}
		>
			{children}
		</div>
	);
}
