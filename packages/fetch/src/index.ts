function defaultIsSessionExpired(response: Response, body: any) {
	return (
		response.status === 401 &&
		response.headers.get('x-auth-error') === 'session-expired'
	);
}

let lastSuccessfulRefresh: number | null = null;
let stopRefreshAttempts = false;

/**
 * A wrapped fetch() function that automatically refreshes the session
 * if it has expired and retries the original request.
 */
export function createFetch({
	isSessionExpired = defaultIsSessionExpired,
	readBody = false,
	refreshSessionEndpoint,
	logoutEndpoint,
	headers,
}: {
	isSessionExpired?: (response: Response, body: any) => boolean;
	readBody?: boolean;
	refreshSessionEndpoint: string;
	logoutEndpoint: string;
	headers?: Record<string, string>;
}): typeof window.fetch {
	return async function fetch(input: any, init: any) {
		// apply credentials=include and any extra headers
		let mutatedInit: RequestInit = {};
		if (typeof input === 'object') {
			mutatedInit = input as RequestInit;
		} else if (typeof init === 'object') {
			mutatedInit = init as RequestInit;
		}
		mutatedInit.credentials = 'include';
		if (headers) {
			const finalHeaders = new Headers(mutatedInit.headers);
			for (const [key, value] of Object.entries(headers)) {
				finalHeaders.append(key, value);
			}
			mutatedInit.headers = finalHeaders;
		}

		let response = await window.fetch.bind(window)(input, init);
		let body: any = undefined;
		if (readBody) {
			const { body: responseBody, clone } = await peekAtResponseBody(response);
			body = responseBody;
			response = clone;
		}

		if (isSessionExpired(response, body)) {
			// if we refreshed less than 5 seconds ago, don't try again.
			// since the refresh was successful, something must be wrong with the cookie
			// configuration... in order to avoid an infinite loop, we'll just log the user out
			if (lastSuccessfulRefresh && Date.now() - lastSuccessfulRefresh < 5000) {
				console.error(
					'session remained expired after a successful refresh. something is wrong. logging out to reset cookies.',
				);
				// log the user out
				await fetch(logoutEndpoint, {
					method: 'POST',
					credentials: 'include',
				});
				return response;
			}
			// if the session expired, we need to refresh it
			const refreshSuccess = await refreshSession(refreshSessionEndpoint);
			if (refreshSuccess) {
				lastSuccessfulRefresh = Date.now();
				// retry the original request
				return fetch(input, init);
			} else {
				// failed to refresh the session - the user needs
				// to log in again. log out just to be safe.
				console.error('failed to refresh session. logging out.');
				await fetch(logoutEndpoint, {
					method: 'POST',
					credentials: 'include',
				});
			}
		}

		return response;
	};
}

export async function refreshSession(endpoint: string) {
	if (stopRefreshAttempts) return false;
	if (!refreshPromise) {
		refreshPromise = refreshSessionInternal(endpoint);
		refreshPromise.finally(() => {
			refreshPromise = null;
		});
	}
	return refreshPromise;
}

let refreshPromise: Promise<boolean> | null = null;
async function refreshSessionInternal(endpoint: string) {
	try {
		const response = await fetch(endpoint, {
			method: 'POST',
			credentials: 'include',
		});
		if (response.ok) {
			const body = await response.json();
			if (body.ok) {
				console.info('session refreshed');
			} else {
				console.error('session refresh failed', body);
				// store a reason as this stuff is hard to debug post-hoc...
				try {
					localStorage.setItem(
						'auth:lastRefreshFailure',
						JSON.stringify({
							timestamp: Date.now(),
							response: {
								status: response.status,
								statusText: response.statusText,
								headers: response.headers,
								body,
							},
						} as Record<string, any>),
					);
				} finally {
				}
			}
		} else if (
			response.status === 401 ||
			response.status === 403 ||
			response.status === 400
		) {
			// a 4xx error means something was wrong with the token... there's really
			// nothing else to do, time to give up.
			console.error('session refresh failed', response.status);
			stopRefreshAttempts = true;
			// store a reason as this stuff is hard to debug post-hoc...
			try {
				localStorage.setItem(
					'auth:lastRefreshFailure',
					JSON.stringify({
						timestamp: Date.now(),
						response: {
							status: response.status,
							statusText: response.statusText,
							headers: response.headers,
							body: await response.json().catch(() => null),
						},
					} as Record<string, any>),
				);
			} finally {
			}
		} else {
			console.error('session refresh failed', response.status);
			// store a reason as this stuff is hard to debug post-hoc...
			try {
				localStorage.setItem(
					'auth:lastRefreshFailure',
					JSON.stringify({
						timestamp: Date.now(),
						response: {
							status: response.status,
							statusText: response.statusText,
							headers: response.headers,
							body: await response.text().catch(() => null),
						},
					} as Record<string, any>),
				);
			} finally {
			}
		}

		return response.ok;
	} catch (e) {
		console.error(e);
		return false;
	}
}

async function peekAtResponseBody(response: Response): Promise<{
	body: any;
	clone: Response;
}> {
	const clone = response.clone();
	try {
		const body = await response.json();
		return {
			body,
			clone,
		};
	} catch (e) {
		console.error(e);
	}
	return {
		body: null,
		clone,
	};
}
