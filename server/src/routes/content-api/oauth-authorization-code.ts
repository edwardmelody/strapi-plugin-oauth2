export default [
  {
    method: 'GET',
    path: '/oauth-authorization-codes',
    handler: 'oauth-authorization-code.find',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'GET',
    path: '/oauth-authorization-codes/:documentId',
    handler: 'oauth-authorization-code.findOne',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'POST',
    path: '/oauth-authorization-codes/authorize',
    handler: 'oauth-authorization-code.authorize',
    config: {
      policies: [],
      middlewares: ['plugin::users-permissions.rateLimit'],
    },
  },
];
