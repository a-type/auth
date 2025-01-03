export interface ServerAdapter<Context = unknown> {
	getRawRequest: (context: Context) => Request;
}

export const rawAdapter: ServerAdapter<Request> = {
	getRawRequest: (context) => context,
};

export const honoAdapter: ServerAdapter<{ req: { raw: Request } }> = {
	getRawRequest: ({ req }) => req.raw,
};
