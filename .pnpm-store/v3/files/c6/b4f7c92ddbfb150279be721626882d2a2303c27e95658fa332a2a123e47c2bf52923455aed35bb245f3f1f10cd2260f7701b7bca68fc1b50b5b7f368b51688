import { ReactNode, useState } from 'react';
import { Particles } from './particlesState.js';
import { createPortal } from 'react-dom';
import { ParticlesProvider } from './ParticleContext.js';

export function ParticleLayer({
	children,
	noPortal,
}: {
	children: ReactNode;
	noPortal?: boolean;
}) {
	const [particles] = useState(() => new Particles({ initialPoolSize: 100 }));

	const canvas = (
		<canvas
			ref={particles.setCanvas}
			className="fixed inset-0 w-full h-full z-overdraw pointer-events-none"
		/>
	);

	return (
		<ParticlesProvider value={particles}>
			{noPortal ? canvas : createPortal(canvas, document.body)}
			{children}
		</ParticlesProvider>
	);
}
