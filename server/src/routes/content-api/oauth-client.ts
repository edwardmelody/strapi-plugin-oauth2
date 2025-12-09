export default [
  {
    method: 'GET',
    path: '/oauth-clients',
    handler: 'oauth-client.find',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'GET',
    path: '/oauth-clients/:documentId',
    handler: 'oauth-client.findOne',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'GET',
    path: '/oauth-clients-authorization/:clientId',
    handler: 'oauth-client.findOneByClientId',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'POST',
    path: '/oauth-clients',
    handler: 'oauth-client.create',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'PUT',
    path: '/oauth-clients/:documentId',
    handler: 'oauth-client.update',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'PUT',
    path: '/oauth-clients-rotate/:documentId',
    handler: 'oauth-client.rotateSecret',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'DELETE',
    path: '/oauth-clients/:documentId',
    handler: 'oauth-client.delete',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'PUT',
    path: '/oauth-clients-keypair/:documentId',
    handler: 'oauth-client.generateKeyPair',
    config: {
      policies: [],
      middlewares: [],
    },
  },
];
