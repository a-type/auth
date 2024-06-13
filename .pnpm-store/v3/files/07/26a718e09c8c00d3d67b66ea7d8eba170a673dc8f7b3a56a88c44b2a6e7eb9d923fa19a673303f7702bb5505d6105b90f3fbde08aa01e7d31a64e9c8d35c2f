import { ReactNode, Suspense } from 'react';
import classNames from 'clsx';

export interface ActionBarProps {
	children: ReactNode;
	className?: string;
	wrap?: boolean;
	disableShadow?: boolean;
}

export function ActionBar({
	children,
	className,
	wrap,
	disableShadow,
	...rest
}: ActionBarProps) {
	return (
		<Suspense fallback={null}>
			<div
				className={classNames(
					'layer-components:(flex flex-row items-center justify-start w-full overflow-hidden relative h-[max-content] transition-[height] springy)',
					'layer-components:[&:empty]:height-0',
					!disableShadow &&
						'after:(content-[""] absolute right-0 top-0 bottom-0 w-50px z-1 bg-gradient-to-l from-wash to-transparent] pointer-events-none)',
					className,
				)}
				{...rest}
			>
				<div
					className={classNames(
						'layer-components:(flex flex-row items-center justify-start w-full overflow-y-hidden overflow-x-auto pr-80px relative h-full) layer-components:[&::-webkit-scrollbar]:hidden',
						wrap && 'layer-variants:flex-wrap',
					)}
				>
					{children}
				</div>
			</div>
		</Suspense>
	);
}
