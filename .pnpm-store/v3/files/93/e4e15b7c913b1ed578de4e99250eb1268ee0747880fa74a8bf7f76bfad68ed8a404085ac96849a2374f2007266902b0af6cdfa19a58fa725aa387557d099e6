import type { Meta, StoryObj } from '@storybook/react';
import { ParticleLayer } from './ParticleLayer.js';
import { Button } from '../button.js';
import { useParticles } from './ParticleContext.js';
import { MouseEvent } from 'react';

const meta = {
	title: 'ParticleLayer',
	component: ParticleLayer,
	argTypes: {},
	parameters: {},
} satisfies Meta<typeof ParticleLayer>;

export default meta;

type Story = StoryObj<typeof ParticleLayer>;

export const Default: Story = {
	render() {
		return (
			<div className="w-full h-[100vh] relative flex flex-col items-center justify-center">
				<ParticleLayer noPortal>
					<DemoButton />
				</ParticleLayer>
			</div>
		);
	},
};

function DemoButton() {
	const particles = useParticles();
	if (!particles) throw new Error('Must be used inside ParticleLayer');
	const burst = (ev: MouseEvent) => {
		particles.addParticles(
			particles.elementExplosion({
				element: ev.currentTarget as HTMLElement,
				count: 10,
			}),
		);
	};
	return (
		<Button size="icon" onClick={burst}>
			💥
		</Button>
	);
}
