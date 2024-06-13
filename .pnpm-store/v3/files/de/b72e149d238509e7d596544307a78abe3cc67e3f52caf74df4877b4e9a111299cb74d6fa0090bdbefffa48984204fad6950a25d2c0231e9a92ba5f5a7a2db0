'use client';

import * as DialogPrimitive from '@radix-ui/react-dialog';
import * as RadioGroupPrimitive from '@radix-ui/react-radio-group';
import {
	ComponentPropsWithoutRef,
	createContext,
	forwardRef,
	useCallback,
	useContext,
	useRef,
	useState,
} from 'react';
import { withClassName } from '../../hooks/withClassName.js';
import useMergedRef from '../../hooks/useMergedRef.js';
import { useParticles } from '../particles.js';
import classNames from 'clsx';
import { CheckIcon, ChevronDownIcon } from '@radix-ui/react-icons';
import { selectTriggerClassName } from '../select.js';
import { useDrag } from '@use-gesture/react';

const StyledOverlay = withClassName(
	DialogPrimitive.Overlay,
	'layer-components:(fixed inset-0 z-dialog-backdrop animate-fade-in animate-duration-200 bg-gray-dark-blend [box-shadow:inset_0_30px_60px_0px_#00001020] border-top-1 border-top-solid border-top-gray-5)',
	'layer-components:[&[data-state=closed]]:animate-fade-out',
	'motion-reduce:animate-none',
);

const StyledContent = withClassName(
	DialogPrimitive.Content,
	'layer-components:(z-dialog fixed shadow-xl bg-white overflow-y-auto flex flex-col border-default)',
	'transform-gpu !motion-reduce:animate-none',
	'layer-components:(left-50% top-50% translate-[-50%] w-90vw max-w-450px max-h-85vh p-6 pt-8 rounded-lg border-b-1 pt-6)',
	'layer-components:(animate-dialog-in [&[data-state=closed]]:animate-dialog-out motion-reduce:animate-none)',
);
const sheetClassName = classNames(
	'layer-variants:lt-sm:(translate-0 bottom-[calc(var(--viewport-bottom-offset,0px)+var(--gesture-y,0px))] left-0 right-0 top-auto h-min-content max-h-[calc(0.85*var(--viewport-height,100vh))] rounded-tl-xl rounded-tr-xl rounded-b-0 p-6 pt-8 w-full max-w-none pb-[calc(3rem+env(safe-area-inset-bottom,0px))] border-b-0)',
	'layer-variants:lt-sm:(animate-ease-in animate-fade-in-up [&[data-state=closed]]:animate-fade-out-down)',
);

export const Content = forwardRef<
	HTMLDivElement,
	ComponentPropsWithoutRef<typeof StyledContent> & {
		outerClassName?: string;
		width?: 'lg' | 'md' | 'sm';
		disableSheet?: boolean;
	}
>(function Content(
	{ children, width, outerClassName, className, disableSheet, ...props },
	ref,
) {
	const particles = useParticles();
	const wasOpenRef = useRef(false);
	const openRef = useCallback(
		(element: HTMLDivElement | null) => {
			if (
				!wasOpenRef.current &&
				element?.getAttribute('data-state') === 'open'
			) {
				wasOpenRef.current = true;

				const matchesSmall =
					!disableSheet &&
					typeof window !== 'undefined' &&
					!window.matchMedia('(min-width:600px)').matches;
				if (!matchesSmall) return;

				setTimeout(() => {
					particles?.addParticles(
						particles.elementExplosion({
							count: 20,
							margin: 40,
							borders: ['top'],
							color: [
								{
									space: 'rgb',
									values: [0, 0, 0],
									opacity: 0.02,
								},
								{
									space: 'rgb',
									values: [0, 0, 0],
									opacity: 0,
								},
							],
							element,
							startRadius: 15,
							endRadius: 0,
							lifespan: 1000,
							force: 0.5,
							drag: 0.01,
							forceFuzz: 0.5,
							angleFuzz: 0.1,
						}),
					);
				}, 180);
			} else if (element?.getAttribute('data-state') === 'closed') {
				wasOpenRef.current = false;
			}
		},
		[particles, disableSheet],
	);

	const gestureRef = useRef<HTMLDivElement>(null);

	const finalRef = useMergedRef(ref, openRef, gestureRef);

	return (
		<DialogPrimitive.Portal>
			<StyledOverlay />
			<StyledContent
				data-dialog-content
				ref={finalRef}
				{...props}
				className={classNames(
					{
						'md:max-w-800px': width === 'lg',
						'max-w-600px': width === 'md',
						'max-w-300px': width === 'sm',
					},
					!disableSheet && sheetClassName,
					outerClassName || className,
				)}
			>
				{!disableSheet && <DialogSwipeHandle />}
				{children}
			</StyledContent>
		</DialogPrimitive.Portal>
	);
});

export const DialogSwipeHandle = forwardRef<
	HTMLDivElement,
	ComponentPropsWithoutRef<'div'>
>(function DialogSwipeHandle({ className, ...props }, ref) {
	const close = useContext(DialogCloseContext);
	const innerRef = useRef<HTMLDivElement>(null);
	useDrag(
		({ swipe: [, swipeY], movement: [, dy], velocity: [, vy], last }) => {
			const content = findParentDialogContent(innerRef.current);
			if (!content) return;

			const contentHeight = content.clientHeight;

			if (last) console.log(swipeY, dy, contentHeight);

			if (last && (swipeY === 1 || dy > contentHeight / 2)) {
				close();
			}
			const gestureY = last ? 0 : -Math.max(0, dy);
			content.style.setProperty('--gesture-y', `${gestureY}px`);
			content.style.setProperty('transition', last ? 'bottom 0.2s' : '');
		},
		{
			target: innerRef,
			axis: 'y',
		},
	);
	const finalRef = useMergedRef(ref, innerRef);
	return (
		<div
			ref={finalRef}
			{...props}
			className={classNames(
				'absolute top-0 left-50% transform-gpu -translate-x-1/2 w-20% py-2 rounded-full cursor-grab sm:hidden touch-none',
				className,
			)}
		>
			<div className="w-full h-[4px] bg-gray-4 rounded-full" />
		</div>
	);
});

function findParentDialogContent(
	element: HTMLElement | null,
): HTMLElement | null {
	if (!element) return null;
	if (element.getAttribute('data-dialog-content')) return element;
	return findParentDialogContent(element.parentElement);
}

const DialogCloseContext = createContext<() => void>(() => {});

const StyledTitle = withClassName(
	DialogPrimitive.Title,
	'font-title color-black text-3xl mb-4 mt-0',
);

const StyledDescription = withClassName(
	DialogPrimitive.Description,
	'mt-3 mb-6 color-gray8 text-md leading-6',
);

// Exports
export const Dialog = (props: DialogPrimitive.DialogProps) => {
	const [innerOpen, innerOnOpenChange] = useState(props.defaultOpen);
	const open = props.open ?? innerOpen;
	const onOpenChange = useCallback(
		(open: boolean) => {
			innerOnOpenChange(open);
			props.onOpenChange?.(open);
		},
		[props.onOpenChange],
	);

	const close = useCallback(() => {
		onOpenChange(false);
	}, [onOpenChange]);

	return (
		<DialogCloseContext.Provider value={close}>
			<DialogPrimitive.Root
				{...props}
				open={open}
				onOpenChange={onOpenChange}
			/>
		</DialogCloseContext.Provider>
	);
};
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogContent = Content;
export const DialogTitle = StyledTitle;
export const DialogDescription = StyledDescription;
export const DialogClose = DialogPrimitive.Close;

export type { DialogProps } from '@radix-ui/react-dialog';

export const DialogActions = withClassName(
	'div',
	'flex justify-end sticky w-full gap-3 items-center bg-white py-3 translate-y-6 flex-wrap',
	'bottom--6',
	'sm:(bottom-0)',
);

export const DialogSelectTrigger = forwardRef<
	HTMLButtonElement,
	DialogPrimitive.DialogTriggerProps
>(function DialogSelectTrigger({ children, className, ...props }, ref) {
	return (
		<DialogPrimitive.Trigger
			className={classNames(selectTriggerClassName, className)}
			{...props}
		>
			<span>{children}</span>
			<ChevronDownIcon />
		</DialogPrimitive.Trigger>
	);
});

export const DialogSelectList = withClassName(
	RadioGroupPrimitive.Root,
	'flex flex-col gap-2 overflow-y-auto p-2',
);

export const DialogSelectItemRoot = withClassName(
	RadioGroupPrimitive.Item,
	'flex items-center gap-3 w-full py-3 px-4 text-left border-none rounded-lg font-normal bg-transparent [&:nth-child(2n+1)]:bg-gray-blend cursor-pointer transition-all',
	'[&[data-state=checked]]:(bg-primary-wash text-primary-dark)',
);

export const DialogSelectItem = forwardRef<
	HTMLButtonElement,
	ComponentPropsWithoutRef<typeof DialogSelectItemRoot>
>(function DialogSelectItem({ children, ...props }, ref) {
	return (
		<DialogSelectItemRoot {...props}>
			<span className="flex-1">{children}</span>
			<RadioGroupPrimitive.Indicator className="flex-0-0-auto">
				<CheckIcon />
			</RadioGroupPrimitive.Indicator>
		</DialogSelectItemRoot>
	);
});
