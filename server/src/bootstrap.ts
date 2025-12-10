import type { Core } from '@strapi/strapi';
import { getOAuthConfig } from './utils/oauth-utils';

const bootstrap = async ({ strapi }: { strapi: Core.Strapi }) => {
  const config = getOAuthConfig(); // ensure config is loaded
  if (!['HS256', 'RS256'].includes(config?.jwtAlg)) {
    throw new Error('OAuth2 plugin: Unsupported JWT algorithm (OAUTH_JWT_ALG) configured');
  } else if (!config.audience) {
    throw new Error('OAuth2 plugin: JWT audience (OAUTH_AUD) is not configured');
  } else if (config.jwtAlg === 'RS256' && !config.jwtPublicKey && !config.jwtPrivateKey) {
    throw new Error(
      'OAuth2 plugin: RSA public/private key pair is not configured for RS256 algorithm (OAUTH_JWT_PUBLIC_KEY and OAUTH_JWT_PRIVATE_KEY)'
    );
  } else if (config.jwtAlg === 'HS256' && !config.jwtSignKey) {
    throw new Error(
      'OAuth2 plugin: JWT sign key (OAUTH_JWT_SIGN_KEY) is not configured for HS256 algorithm'
    );
  }

  const actions = [
    {
      section: 'plugins',
      displayName: 'Read global settings',
      uid: 'oauth-global-setting.read',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Update global settings',
      uid: 'oauth-global-setting.update',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Read available scopes',
      uid: 'oauth.read',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Create client',
      uid: 'oauth-client.create',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Rotate client secret',
      uid: 'oauth-client.rotate',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Read clients',
      uid: 'oauth-client.read',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Update client',
      uid: 'oauth-client.update',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Delete client',
      uid: 'oauth-client.delete',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Read access tokens',
      uid: 'oauth-access-token.read',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Revoke access token',
      uid: 'oauth-access-token.revoke',
      pluginName: 'strapi-plugin-oauth2',
    },
    {
      section: 'plugins',
      displayName: 'Generate client keypair',
      uid: 'oauth-client.generate-keypair',
      pluginName: 'strapi-plugin-oauth2',
    },
  ];

  // register all actions
  strapi.admin.services.permission.actionProvider.registerMany(actions);

  // create system api key
  let accessKey;
  const tokenExists = await strapi.service('admin::api-token').exists({
    name: 'OAuth2 Plugin System Token',
  });
  if (!tokenExists) {
    const result = await strapi.service('admin::api-token').create({
      name: 'OAuth2 Plugin System Token',
      description: 'System token for Strapi OAuth2 plugin to access internal APIs',
      type: 'custom',
      lifespan: null,
      permissions: [],
    });
    accessKey = result.accessKey;
  }

  // initial global setting
  const globalSettings = await strapi
    .documents('plugin::strapi-plugin-oauth2.oauth-global-setting')
    .findFirst();
  if (!globalSettings) {
    await strapi.documents('plugin::strapi-plugin-oauth2.oauth-global-setting').create({
      data: {
        scopes: [],
      },
    });
  }
};

export default bootstrap;
