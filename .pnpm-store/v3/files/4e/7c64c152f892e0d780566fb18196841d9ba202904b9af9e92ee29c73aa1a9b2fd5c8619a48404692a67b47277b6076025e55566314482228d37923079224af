import { fractionToText } from '@a-type/utils';
import { MinusIcon, PlusIcon } from '@radix-ui/react-icons';
import classNames from 'clsx';
import { ReactNode } from 'react';
import { Button } from '../button.js';

export interface NumberStepperProps {
	value: number;
	onChange: (value: number) => void;
	highlightChange?: boolean;
	steps?: number[];
	increment?: number;
	renderValue?: (value: number) => ReactNode;
	className?: string;
	disabled?: boolean;
}

export function NumberStepper({
	value,
	onChange,
	highlightChange,
	steps,
	increment: incrementAmount = 1,
	renderValue = fractionToText,
	className,
	disabled,
	...rest
}: NumberStepperProps) {
	const index = steps?.indexOf(value) ?? 0;

	const increment = () => {
		if (steps) {
			if (index === steps.length - 1) {
				return;
			}
			onChange(steps[index + 1]);
		} else {
			onChange(value + incrementAmount);
		}
	};

	const decrement = () => {
		if (steps) {
			if (index === 0) {
				return;
			}
			onChange(steps[index - 1]);
		} else {
			onChange(value - incrementAmount);
		}
	};

	const canIncrement = !disabled && (steps ? index < steps.length - 1 : true);
	const canDecrement = !disabled && (steps ? index > 0 : true);

	return (
		<div
			className={classNames(
				'layer-components:(flex items-center border-default rounded-full overflow-hidden w-min-content flex-shrink-0 bg-white shadow-sm)',
				disabled &&
					'layer-variants:(border-gray-dark-blend bg-transparent shadow-none)',
				{
					'layer-variants:(bg-accent-wash color-black)':
						!!highlightChange && value !== 1,
				},
				className,
			)}
			{...rest}
		>
			<Button color="ghost" onClick={decrement} disabled={!canDecrement}>
				<MinusIcon />
			</Button>
			<div className="w-80px text-center">{renderValue(value)}</div>
			<Button color="ghost" onClick={increment} disabled={!canIncrement}>
				<PlusIcon />
			</Button>
		</div>
	);
}
