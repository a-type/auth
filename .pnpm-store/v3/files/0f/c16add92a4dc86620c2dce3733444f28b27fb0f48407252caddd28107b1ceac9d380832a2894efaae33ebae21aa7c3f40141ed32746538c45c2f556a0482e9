'use client';

import classNames from 'clsx';
import useMergedRef from '../../hooks/useMergedRef.js';
import {
	ChangeEvent,
	forwardRef,
	HTMLProps,
	useCallback,
	useEffect,
	useLayoutEffect,
	useRef,
	useState,
} from 'react';
import { inputClassName } from '../input.js';

export interface TextAreaProps
	extends Omit<HTMLProps<HTMLTextAreaElement>, 'ref'> {
	className?: string;
	autoSize?: boolean;
	autoSelect?: boolean;
	// if auto-size, pad the height by this many px
	padBottomPixels?: number;
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(
	function TextArea(
		{
			autoSize,
			autoSelect,
			onFocus,
			className,
			rows,
			padBottomPixels = 0,
			onChange,
			...rest
		},
		ref,
	) {
		const innerRef = useRef<HTMLTextAreaElement>(null);
		const finalRef = useMergedRef(innerRef, ref);

		const [innerValue, setInnerValue] = useState('');
		const finalValue = rest.value ?? innerValue;

		// TODO: can layout effect be avoided? useEffect shows a flash of the wrong size
		useLayoutEffect(() => {
			if (!autoSize) return;
			const element = innerRef.current;
			if (element) {
				if (element.value !== '' || padBottomPixels) {
					element!.style.height = 'auto';
					const baseHeight = element.scrollHeight;
					element.style.height = baseHeight + padBottomPixels + 'px';
				}
			}
		}, [autoSize, padBottomPixels, finalValue]);

		const handleChange = useCallback(
			(e: ChangeEvent<HTMLTextAreaElement>) => {
				setInnerValue((e.target as HTMLTextAreaElement).value);
				if (onChange) {
					onChange(e);
				}
			},
			[onChange],
		);

		const handleFocus = useCallback(
			(e: React.FocusEvent<HTMLTextAreaElement>) => {
				if (autoSelect) {
					e.target.select();
				}
				if (onFocus) {
					onFocus(e);
				}
			},
			[autoSelect, onFocus],
		);

		return (
			<textarea
				ref={finalRef}
				className={classNames(
					inputClassName,
					'layer-components:([font-family:inherit] text-inherit overflow-hidden)',
					{
						'layer-components:[resize:vertical]': !autoSize,
						'layer-components:[resize:none]': autoSize,
					},
					className,
				)}
				rows={autoSize ? 1 : rows}
				onChange={handleChange}
				onFocus={handleFocus}
				{...rest}
			/>
		);
	},
);
