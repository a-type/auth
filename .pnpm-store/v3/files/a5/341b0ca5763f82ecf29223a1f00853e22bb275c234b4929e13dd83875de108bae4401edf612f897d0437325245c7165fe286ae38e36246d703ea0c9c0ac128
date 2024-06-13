import { withClassName } from '../../hooks.js';
import * as SliderPrimitive from '@radix-ui/react-slider';

export const SliderRoot = withClassName(
	SliderPrimitive.Root,
	'layer-components:(relative flex items-center select-none touch-none w-full h-30px translate-z-0)',
);
export const SliderTrack = withClassName(
	SliderPrimitive.Track,
	'layer-components:(bg-transparent relative grow rounded-full h-9px border border-1px border-solid border-black)',
);
export const SliderRange = withClassName(
	SliderPrimitive.Range,
	'layer-components:(absolute bg-accent rounded-full h-full)',
	'layer-variants:[&[data-color=primary]]:bg-primary',
);
export const SliderThumb = withClassName(
	SliderPrimitive.Thumb,
	'layer-components:(block w-5 h-5 bg-white shadow-sm rounded-full ring-2 ring-black touch-none transition-all)',
	'layer-components:hover:(shadow-md)',
	'layer-components:active:(shadow-lg ring-4 ring-accent ring-opacity-50 bg-accent-light)',
	'layer-components:focus-visible:(shadow-lg ring-4 ring-accent ring-opacity-50 outline-none bg-accent-light)',
	'layer-components:focus:(outline-none)',
	'layer-components:disabled:(opacity-50)',
	'layer-variants:[&[data-color=primary]]:active:(bg-primary-light ring-primary)',
	'layer-variants:[&[data-color=primary]]:focus-visible:(bg-primary-light ring-primary)',
);

interface SliderProps extends SliderPrimitive.SliderProps {
	label?: string;
	color?: 'default' | 'primary';
}

export function Slider({ label, color, ...props }: SliderProps) {
	return (
		<SliderRoot {...props}>
			<SliderTrack>
				<SliderRange data-color={color} />
			</SliderTrack>
			<SliderThumb aria-label={label} data-color={color} />
		</SliderRoot>
	);
}
