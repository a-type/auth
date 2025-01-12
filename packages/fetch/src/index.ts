function defaultIsSessionExpired(response: Response, body: any) {
	return (
		response.status === 401 &&
		response.headers.get('x-auth-error') === 'session-expired'
	);
}

/**
 * A wrapped fetch() function that automatically refreshes the session
 * if it has expired and retries the original request.
 */
export function createFetch({
	isSessionExpired = defaultIsSessionExpired,
	readBody = false,
	refreshSessionEndpoint,
	headers,
}: {
	isSessionExpired?: (response: Response, body: any) => boolean;
	readBody?: boolean;
	refreshSessionEndpoint: string;
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
			// if the session expired, we need to refresh it
			const refreshSuccess = await refreshSession(refreshSessionEndpoint);
			if (refreshSuccess) {
				// retry the original request
				return fetch(input, init);
			} else {
				// failed to refresh the session - the user needs
				// to log in again
			}
		}

		return response;
	};
}

export async function refreshSession(endpoint: string) {
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
			}
		} else if (response.status === 401 || response.status === 403) {
			console.error('session refresh failed', response.status);
		} else {
			console.error('session refresh failed', response.status);
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
