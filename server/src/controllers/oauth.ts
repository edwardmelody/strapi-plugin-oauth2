import type { Core } from '@strapi/strapi';

const controller = ({ strapi }: { strapi: Core.Strapi }) => ({
  async getAvailableScopes(ctx) {
    const scopes: Record<string, Array<{ action: string; name: string }>> = {};

    const actions = await strapi
      .plugin('users-permissions')
      .service('users-permissions')
      .getActions();

    for (const [k, v] of Object.entries(actions)) {
      let key = k;
      for (const [k2, v2] of Object.entries((v as any).controllers || {})) {
        key = `${k}.${k2}`;
        if (!scopes[key]) {
          scopes[key] = [];
        }
        for (const action in v2 as any) {
          scopes[key].push({
            name: `${key}.${action}`,
            action: action,
          });
        }
      }
    }

    ctx.send(scopes);
  },
});

export default controller;
