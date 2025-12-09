export default [
  {
    method: 'GET',
    path: '/oauth-global-settings',
    handler: 'oauth-global-setting.find',
    config: {
      policies: [],
      middlewares: [],
    },
  },
  {
    method: 'PUT',
    path: '/oauth-global-settings/:documentId',
    handler: 'oauth-global-setting.update',
    config: {
      policies: [],
      middlewares: [],
    },
  },
];
