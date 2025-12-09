const pluginPermissions = {
  readGlobalSettings: [
    { action: 'plugin::strapi-plugin-oauth2.oauth-global-setting.read', subject: null },
  ],
  updateGlobalSettings: [
    { action: 'plugin::strapi-plugin-oauth2.oauth-global-setting.update', subject: null },
  ],
  readScopes: [{ action: 'plugin::strapi-plugin-oauth2.oauth.read', subject: null }],
  createClient: [{ action: 'plugin::strapi-plugin-oauth2.oauth-client.create', subject: null }],
  rotateClient: [{ action: 'plugin::strapi-plugin-oauth2.oauth-client.rotate', subject: null }],
  readClients: [{ action: 'plugin::strapi-plugin-oauth2.oauth-client.read', subject: null }],
  updateClient: [{ action: 'plugin::strapi-plugin-oauth2.oauth-client.update', subject: null }],
  deleteClient: [{ action: 'plugin::strapi-plugin-oauth2.oauth-client.delete', subject: null }],
  readAccessTokens: [
    { action: 'plugin::strapi-plugin-oauth2.oauth-access-token.read', subject: null },
  ],
  revokeAccessToken: [
    { action: 'plugin::strapi-plugin-oauth2.oauth-access-token.revoke', subject: null },
  ],
  generateClientKeyPair: [
    { action: 'plugin::strapi-plugin-oauth2.oauth-client.generate-keypair', subject: null },
  ],
};

export default pluginPermissions;
