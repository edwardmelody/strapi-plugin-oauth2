export default [
  {
    method: 'GET',
    path: '/oauth-access-tokens',
    handler: 'oauth-access-token.find',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'GET',
    path: '/oauth-access-tokens/:documentId',
    handler: 'oauth-access-token.findOne',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'POST',
    path: '/oauth-access-tokens/token',
    handler: 'oauth-access-token.token',
    config: {
      policies: [],
      middlewares: ['plugin::users-permissions.rateLimit'],
    },
  },
  {
    method: 'POST',
    path: '/oauth-access-tokens/revoke',
    handler: 'oauth-access-token.revoke',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'POST',
    path: '/oauth-access-tokens/introspect',
    handler: 'oauth-access-token.introspect',
    config: {
      policies: [],
      middlewares: [],
    },
  },
];
