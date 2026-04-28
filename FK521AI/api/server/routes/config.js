const express = require('express');
const { isEnabled, getBalanceConfig } = require('@fk521ai/api');
const { logger, getTenantId } = require('@fk521ai/data-schemas');
const { getLdapConfig } = require('~/server/services/Config/ldap');
const { getAppConfig } = require('~/server/services/Config/app');
const { getConfigRevision, subscribeConfigUpdates } = require('~/server/services/Config/realtime');
const { readSystemSettings, hasEmailConfig, getStartupAdminUI } = require('~/server/utils/adminSystemConfig');
const { getRequestBaseUrl } = require('~/server/utils/requestBaseUrl');

const router = express.Router();
const sharedLinksEnabled =
  process.env.ALLOW_SHARED_LINKS === undefined || isEnabled(process.env.ALLOW_SHARED_LINKS);

const publicSharedLinksEnabled =
  sharedLinksEnabled && isEnabled(process.env.ALLOW_SHARED_LINKS_PUBLIC);

const sharePointFilePickerEnabled = isEnabled(process.env.ENABLE_SHAREPOINT_FILEPICKER);
const openidReuseTokens = isEnabled(process.env.OPENID_REUSE_TOKENS);

function isBirthday() {
  const today = new Date();
  return today.getMonth() === 1 && today.getDate() === 11;
}


function hasEnvVars(...names) {
  return names.every((name) => typeof process.env[name] === 'string' && process.env[name].trim() !== '');
}

function isSocialProviderConfigured(provider) {
  switch (provider) {
    case 'google':
      return hasEnvVars('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL');
    case 'facebook':
      return hasEnvVars('FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET', 'FACEBOOK_CALLBACK_URL');
    case 'github':
      return hasEnvVars('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_CALLBACK_URL');
    case 'discord':
      return hasEnvVars('DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET', 'DISCORD_CALLBACK_URL');
    case 'apple':
      return hasEnvVars('APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY_PATH');
    case 'openid':
      return hasEnvVars('OPENID_CLIENT_ID', 'OPENID_CLIENT_SECRET', 'OPENID_ISSUER', 'OPENID_SCOPE', 'OPENID_SESSION_SECRET');
    case 'saml':
      return hasEnvVars('SAML_ENTRY_POINT', 'SAML_ISSUER', 'SAML_CERT', 'SAML_SESSION_SECRET');
    default:
      return false;
  }
}

function buildSocialLoginPayload(appConfig) {
  const configuredProviders = Array.isArray(appConfig?.registration?.socialLogins)
    ? appConfig.registration.socialLogins.map((provider) => String(provider).trim().toLowerCase()).filter(Boolean)
    : [];
  const envAllowsSocialLogin =
    process.env.ALLOW_SOCIAL_LOGIN === undefined || isEnabled(process.env.ALLOW_SOCIAL_LOGIN);
  const socialLogins = envAllowsSocialLogin
    ? configuredProviders.filter((provider) => isSocialProviderConfigured(provider))
    : [];

  return {
    socialLogins,
    socialLoginEnabled: socialLogins.length > 0,
    discordLoginEnabled: socialLogins.includes('discord'),
    facebookLoginEnabled: socialLogins.includes('facebook'),
    githubLoginEnabled: socialLogins.includes('github'),
    googleLoginEnabled: socialLogins.includes('google'),
    appleLoginEnabled: socialLogins.includes('apple'),
    openidLoginEnabled: socialLogins.includes('openid'),
    openidAutoRedirect: socialLogins.includes('openid') && isEnabled(process.env.OPENID_AUTO_REDIRECT),
    samlLoginEnabled: socialLogins.includes('saml'),
  };
}

function buildSharedPayload(req) {
  const ldap = getLdapConfig();
  const systemSettings = readSystemSettings();

  /** @type {Partial<TStartupConfig>} */
  const payload = {
    appTitle: process.env.APP_TITLE || 'FK521AI',
    discordLoginEnabled: false,
    facebookLoginEnabled: false,
    githubLoginEnabled: false,
    googleLoginEnabled: false,
    appleLoginEnabled: false,
    openidLoginEnabled: false,
    openidLabel: process.env.OPENID_BUTTON_LABEL || 'Continue with OpenID',
    openidImageUrl: process.env.OPENID_IMAGE_URL,
    openidAutoRedirect: false,
    samlLoginEnabled: false,
    samlLabel: process.env.SAML_BUTTON_LABEL,
    samlImageUrl: process.env.SAML_IMAGE_URL,
    serverDomain: getRequestBaseUrl(req),
    emailLoginEnabled: systemSettings.auth.allowEmailLogin,
    registrationEnabled: !ldap?.enabled && systemSettings.auth.allowRegistration,
    socialLoginEnabled: false,
    emailEnabled: hasEmailConfig(systemSettings),
    passwordResetEnabled: systemSettings.auth.allowPasswordReset,
    showBirthdayIcon:
      isBirthday() ||
      isEnabled(process.env.SHOW_BIRTHDAY_ICON) ||
      process.env.SHOW_BIRTHDAY_ICON === '',
    helpAndFaqURL: process.env.HELP_AND_FAQ_URL || '/',
    sharedLinksEnabled,
    publicSharedLinksEnabled,
    analyticsGtmId: process.env.ANALYTICS_GTM_ID,
    openidReuseTokens,
  };

  payload.minPasswordLength = systemSettings.auth.minPasswordLength;
  payload.adminUI = getStartupAdminUI(systemSettings);

  if (ldap) {
    payload.ldap = ldap;
  }

  if (typeof process.env.CUSTOM_FOOTER === 'string') {
    payload.customFooter = process.env.CUSTOM_FOOTER;
  }

  return payload;
}



router.get('/events', function (req, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  const writeEvent = (name, payload) => {
    if (res.writableEnded) {
      return;
    }
    res.write(`event: ${name}
data: ${JSON.stringify(payload)}

`);
    res.flush?.();
  };

  writeEvent('ready', {
    revision: getConfigRevision(),
    changedKeys: ['endpoints', 'startupConfig'],
    updatedAt: new Date().toISOString(),
  });

  const unsubscribe = subscribeConfigUpdates((event) => {
    writeEvent('config_updated', event);
  });

  const heartbeat = setInterval(() => {
    if (!res.writableEnded) {
      res.write(`: keep-alive ${Date.now()}\n\n`);
      res.flush?.();
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
    if (!res.writableEnded) {
      res.end();
    }
  });
});

router.get('/', async function (req, res) {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const sharedPayload = buildSharedPayload(req);

    if (!req.user) {
      const tenantId = getTenantId();
      const baseConfig = await getAppConfig(tenantId ? { tenantId } : { baseOnly: true });

      /** @type {Partial<TStartupConfig>} */
      const payload = {
        ...sharedPayload,
        ...buildSocialLoginPayload(baseConfig),
        turnstile: baseConfig?.turnstileConfig,
      };

      const interfaceConfig = baseConfig?.interfaceConfig;
      if (interfaceConfig?.privacyPolicy || interfaceConfig?.termsOfService) {
        payload.interface = {};
        if (interfaceConfig.privacyPolicy) {
          payload.interface.privacyPolicy = interfaceConfig.privacyPolicy;
        }
        if (interfaceConfig.termsOfService) {
          payload.interface.termsOfService = interfaceConfig.termsOfService;
        }
      }

      return res.status(200).send(payload);
    }

    const appConfig = await getAppConfig({
      role: req.user.role,
      userId: req.user.id,
      tenantId: req.user.tenantId || getTenantId(),
    });

    const balanceConfig = getBalanceConfig(appConfig);

    /** @type {TStartupConfig} */
    const payload = {
      ...sharedPayload,
      ...buildSocialLoginPayload(appConfig),
      interface: appConfig?.interfaceConfig,
      turnstile: appConfig?.turnstileConfig,
      modelSpecs: appConfig?.modelSpecs,
      balance: balanceConfig,
      bundlerURL: process.env.SANDPACK_BUNDLER_URL,
      staticBundlerURL: process.env.SANDPACK_STATIC_BUNDLER_URL,
      sharePointFilePickerEnabled,
      sharePointBaseUrl: process.env.SHAREPOINT_BASE_URL,
      sharePointPickerGraphScope: process.env.SHAREPOINT_PICKER_GRAPH_SCOPE,
      sharePointPickerSharePointScope: process.env.SHAREPOINT_PICKER_SHAREPOINT_SCOPE,
      conversationImportMaxFileSize: process.env.CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES
        ? parseInt(process.env.CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES, 10)
        : 0,
    };

    return res.status(200).send(payload);
  } catch (err) {
    logger.error('Error in startup config', err);
    return res.status(500).send({ error: 'Failed to load startup config' });
  }
});

module.exports = router;
