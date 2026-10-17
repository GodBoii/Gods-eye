import { startApplicationChrome } from '../app/startupChrome.js';
export function startStandaloneChrome(options) {
  return startApplicationChrome({
    initializeSettings: null,
    initializeWelcome: null,
    ...options,
  });
}
