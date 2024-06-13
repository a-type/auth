export function assert(
  condition: any,
  message: string = 'assertion failed',
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

export function nonNilFilter<T>(value: T | null | undefined): value is T {
  return value != null;
}
