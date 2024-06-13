import classNames from 'clsx';
import { forwardRef, ButtonHTMLAttributes, memo } from 'react';
import { Spinner } from '../spinner.js';
import { getButtonClassName } from './classes.js';
import { Slot } from '@radix-ui/react-slot';
import { Icon } from '../icon.js';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
	color?:
		| 'primary'
		| 'default'
		| 'ghost'
		| 'destructive'
		| 'ghostDestructive'
		| 'ghostAccent'
		| 'accent'
		| 'contrast'
		| 'unstyled';
	size?: 'default' | 'small' | 'icon';
	toggled?: boolean;
	align?: 'start' | 'stretch' | 'end';
	visuallyDisabled?: boolean;
	loading?: boolean;
	asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
	function Button(
		{
			className,
			color,
			size,
			toggled,
			align,
			visuallyDisabled,
			loading,
			children,
			disabled,
			asChild,
			...props
		},
		ref,
	) {
		const Comp = asChild ? Slot : 'button';
		const buttonProps = {
			ref: ref,
			...props,
			disabled: disabled || loading,
			'data-disabled': visuallyDisabled,
			tabIndex: visuallyDisabled ? -1 : undefined,
			className: classNames(
				getButtonClassName({
					color,
					size,
					toggleable: toggled !== undefined,
					align,
				}),
				className,
			),
		};
		// set state when toggleable
		if (toggled !== undefined) {
			buttonProps['aria-pressed'] = toggled;
		}

		if (asChild) {
			// avoid rendering loading spinner with asChild
			return <Comp {...buttonProps}>{children}</Comp>;
		}

		return (
			<Comp {...buttonProps}>
				{loading && <Spinner size={16} className="inline-block w-1em h-1em" />}
				{toggled !== undefined && <ToggleIndicator value={toggled} />}
				{children}
			</Comp>
		);
	},
);

const ToggleIndicator = memo(function ToggleIndicator({
	value,
}: {
	value: boolean;
}) {
	return (
		<Icon
			aria-hidden
			name="check"
			className="transition-width w-0 ml--1"
			style={{
				width: value ? '15px' : 0,
			}}
		/>
	);
});
