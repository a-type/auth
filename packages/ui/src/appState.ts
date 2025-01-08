export function handleAppState(handler: (appState: any) => void) {
  const appState = new URLSearchParams(window.location.search).get('appState');
  if (appState) {
    handler(JSON.parse(appState));
  }
}
