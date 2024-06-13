import { useEffect, useState } from 'react';

/**
 * Applies bottom offset px as a CSS custom property to the document root.
 */
export function useVisualViewportOffset() {
	useEffect(() => {
		const viewport =
			typeof window === 'undefined' ? undefined : window.visualViewport;

		if (!viewport) {
			return;
		}

		const update = () => {
			document.documentElement.style.setProperty(
				'--viewport-bottom-offset',
				`${window.innerHeight - viewport.height}px`,
			);
			document.documentElement.style.setProperty(
				'--viewport-height',
				`${viewport.height}px`,
			);
		};

		update();

		window.addEventListener('scroll', update, { passive: true });
		viewport.addEventListener('resize', update);

		return () => {
			viewport.removeEventListener('resize', update);
			window.removeEventListener('scroll', update);
		};
	}, []);
}
