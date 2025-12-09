export default [
  {
    method: 'GET',
    path: '/global-settings',
    handler: 'oauth-global-setting.find',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-global-setting.read'],
          },
        },
      ],
    },
  },
  {
    method: 'PUT',
    path: '/global-settings/:documentId',
    handler: 'oauth-global-setting.update',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-global-setting.update'],
          },
        },
      ],
    },
  },
  {
    method: 'GET',
    path: '/scopes',
    handler: 'oauth.getAvailableScopes',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth.read'],
          },
        },
      ],
    },
  },
  {
    method: 'POST',
    path: '/clients',
    handler: 'oauth-client.create',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.create'],
          },
        },
      ],
    },
  },
  {
    method: 'PUT',
    path: '/clients-rotate/:documentId',
    handler: 'oauth-client.rotateSecret',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.rotate'],
          },
        },
      ],
    },
  },
  {
    method: 'GET',
    path: '/clients',
    handler: 'oauth-client.find',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.read'],
          },
        },
      ],
    },
  },
  {
    method: 'PUT',
    path: '/clients/:documentId',
    handler: 'oauth-client.update',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.update'],
          },
        },
      ],
    },
  },
  {
    method: 'DELETE',
    path: '/clients/:documentId',
    handler: 'oauth-client.delete',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.delete'],
          },
        },
      ],
    },
  },
  {
    method: 'GET',
    path: '/access-tokens',
    handler: 'oauth-access-token.find',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-access-token.read'],
          },
        },
      ],
    },
  },
  {
    method: 'POST',
    path: '/access-tokens/revoke',
    handler: 'oauth-access-token.revoke',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-access-token.revoke'],
          },
        },
      ],
    },
  },
  {
    method: 'PUT',
    path: '/clients-keypair/:documentId',
    handler: 'oauth-client.generateKeyPair',
    config: {
      policies: [
        {
          name: 'admin::hasPermissions',
          config: {
            actions: ['plugin::oauth2.oauth-client.generate-keypair'],
          },
        },
      ],
    },
  },
];
