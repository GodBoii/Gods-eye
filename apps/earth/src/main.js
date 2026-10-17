import { createStandaloneApplication } from './standalone/application.js';
import { describeError } from './standalone/errors.js';
import { t } from './i18n/index.js';
import { mountFreeConsole } from './free/console.js';

const application = createStandaloneApplication({
  googleApiKey: '',
  cesiumToken: '',
  allowQaRegistration: false,
});

application.start().then(() => mountFreeConsole(application)).catch((error) => {
  console.error("God's Eye View initialization failed:", error);
  const loaderStatus = document.querySelector('#loading-screen .loader-status');
  loaderStatus.textContent = t('Error: {message}', {
    message: describeError(error),
  });
  loaderStatus.style.color = '#ff4444';
});

export { application };
