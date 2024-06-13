export function debounce<Fn extends (...args: any[]) => void>(
  callback: Fn,
  delay: number,
): Fn {
  let timeout: NodeJS.Timeout | undefined;
  return ((...args) => {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
    timeout = setTimeout(() => {
      timeout = undefined;
      callback(...args);
    }, delay);
  }) as Fn;
}

export function throttle<Fn extends (...args: any[]) => void>(
  callback: Fn,
  delay: number,
): Fn {
  let lastTime = 0;
  return ((...args) => {
    const now = Date.now();
    // makes sure the latest value is always sent after throttling ends
    const finalizer = debounce(callback, delay);
    if (now - lastTime >= delay) {
      lastTime = now;
      callback(...args);
    }
    finalizer(...args);
  }) as Fn;
}
