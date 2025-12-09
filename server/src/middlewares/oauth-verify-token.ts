import type { OAuthJwtPayload } from '../types/oauth';
import { getOAuthConfig } from '../utils/oauth-utils';
import jwt from 'jsonwebtoken';
import type { Context, Next } from 'koa';

export default () => {
  return async (ctx: Context, next: Next) => {
    const auth = ctx.request.header.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      // ไม่มี token -> ไปต่อระบบเดิม (users-permissions) handle
      return await next();
    }

    const { audience } = getOAuthConfig();
    const token = auth.slice('Bearer '.length);

    const decoded = jwt.decode(token) as OAuthJwtPayload;
    if (!decoded?.aud || decoded.aud !== audience) {
      // the token is not meant for oauth2 API
      return await next();
    }

    const introspect = await strapi
      .service('plugin::oauth2.oauth-access-token')
      .introspectByToken(token);
    if (!introspect || !introspect.active) {
      return ctx.throw(401, 'token_user_mismatch');
    }

    // rewrite authorization header for downstream usage
    const oauthUser = await strapi.documents('plugin::oauth2.oauth-user').findFirst({
      filters: {
        clientId: introspect.clientId,
        userDocumentId: introspect.userId,
      },
    });
    if (!oauthUser) {
      return ctx.throw(401, 'token_user_mismatch');
    }
    // no longer need to use oauth token form global setting
    // const globalSetting = await strapi.documents('plugin::oauth2.oauth-global-setting').findFirst();
    // ctx.request.headers['authorization'] = `Bearer ${globalSetting.systemAccessKey}`;
    ctx.request.headers['authorization'] = `Bearer ${oauthUser.apiTokenAccessKey}`;

    // attach info to ctx.state
    ctx.state.oauth = {
      grantType: introspect.grantType,
      clientId: introspect.clientId,
      userId: introspect.userId,
      scope: introspect.scope,
      jti: introspect.jti,
      raw: introspect,
    };
    await next();
  };
};
