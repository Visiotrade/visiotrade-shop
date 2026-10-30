'use strict';
(function () {
  // URL parameters are only a loading hint, NOT identity/authentication evidence.
  const params = new URLSearchParams(window.location.hash.slice(1));
  const platform = params.get('tgWebAppPlatform');
  const version = params.get('tgWebAppVersion');
  const hasContext = !!params.get('tgWebAppData') && /^\d+\.\d+$/.test(version || '') &&
    ['android', 'android_x', 'ios', 'macos', 'tdesktop', 'web', 'weba', 'webk', 'unigram'].includes(platform);
  window.visioTelegramReady = hasContext ? new Promise(resolve => {
    const script = document.createElement('script');
    let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = null;
      resolve(value);
    };
    const timer = setTimeout(() => { script.remove(); finish(null); }, 4000);
    script.src = 'https://telegram.org/js/telegram-web-app.js';
    script.async = true;
    script.referrerPolicy = 'no-referrer';
    script.onload = () => finish(window.Telegram?.WebApp || null);
    script.onerror = () => { script.remove(); finish(null); };
    document.head.appendChild(script);
  }) : Promise.resolve(null);
})();
