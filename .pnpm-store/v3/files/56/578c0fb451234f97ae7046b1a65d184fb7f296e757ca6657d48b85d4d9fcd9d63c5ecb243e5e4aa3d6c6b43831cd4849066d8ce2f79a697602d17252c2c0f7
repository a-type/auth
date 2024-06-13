import { ReactNode } from 'react';
import { ParticleLayer } from '../particles.js';
import { IconSpritesheet } from '../icon.js';
import { Toaster, ToastPosition } from 'react-hot-toast';

export interface ProviderProps {
	children?: ReactNode;
	disableParticles?: boolean;
	toastPosition?: ToastPosition;
	toastContainerClassName?: string;
}

/**
 * Provides all the stuff for all global junk.
 */
export function Provider({
	children,
	disableParticles,
	toastPosition = 'bottom-center',
	toastContainerClassName,
}: ProviderProps) {
	const otherStuff = (
		<>
			<IconSpritesheet />
			<Toaster
				position={toastPosition}
				containerClassName={toastContainerClassName}
			/>
		</>
	);

	if (disableParticles)
		return (
			<>
				{children}
				{otherStuff}
			</>
		);

	return (
		<ParticleLayer>
			{children}
			{otherStuff}
		</ParticleLayer>
	);
}
