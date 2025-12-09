import { factories } from '@strapi/strapi';

import { handleError } from '../utils/error';

import qs from 'qs';

import utils from '@strapi/utils';
const { ValidationError, UnauthorizedError } = utils.errors;

export default factories.createCoreController(
  'plugin::oauth2.oauth-authorization-code',
  ({ strapi }) => ({
    async authorize(ctx) {
      const { approve, clientId, redirectUri, scopes, state, codeChallenge, codeChallengeMethod } =
        ctx.request.body;
      try {
        if (!ctx.state.user) throw new UnauthorizedError('login_required');

        if (!approve) {
          const q = qs.stringify({ error: 'access_denied', state });
          return {
            redirectUri: `${redirectUri}?${q}`,
          };
        }

        // create Authorization Code
        const rawCode = await strapi
          .plugin('oauth2')
          .service('oauth-authorization-code')
          .createAuthorizationCode({
            clientId,
            userDocumentId: ctx.state.user.documentId,
            redirectUri,
            scopes,
            codeChallenge,
            codeChallengeMethod,
          });

        // redirect back with code and state
        const q = qs.stringify({ code: rawCode, state });
        return {
          redirectUri: `${redirectUri}?${q}`,
        };
      } catch (err) {
        const q = qs.stringify({ error: err.message || 'access_denied', state });
        return {
          redirectUri: `${redirectUri}?${q}`,
        };
      }
    },
    async introspect(ctx) {
      try {
        // protect this endpoint (basic auth with admin or client creds)
        const token = ctx.request.body.token;
        if (!token) throw new ValidationError('token is required');
        const res = await strapi
          .service('plugin::oauth2.oauth-access-token')
          .introspectByToken(token);
        return res;
      } catch (err) {
        handleError(ctx, err);
      }
    },

    async revoke(ctx) {
      try {
        const jti = ctx.request.body.jti;
        if (!jti) throw new ValidationError('jti is required');

        const ok = await strapi
          .service('plugin::oauth2.oauth-access-token')
          .revokeTokenByJti(jti, ctx.state.user?.documentId);
        return {
          revoked: ok,
        };
      } catch (err) {
        handleError(ctx, err);
      }
    },
  })
);
