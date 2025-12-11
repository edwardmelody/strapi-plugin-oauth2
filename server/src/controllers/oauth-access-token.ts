import { factories } from '@strapi/strapi';

import { handleError } from '../utils/error';

import utils from '@strapi/utils';
import { UnauthorizedError } from '@strapi/utils/dist/errors';
const { ValidationError } = utils.errors;

export default factories.createCoreController(
  'plugin::strapi-plugin-oauth2.oauth-access-token',
  ({ strapi }) => ({
    async introspect(ctx) {
      try {
        // protect this endpoint (basic auth with admin or client creds)
        const token = ctx.request.body.token;
        if (!token) throw new ValidationError('token is required');
        const res = await strapi
          .service('plugin::strapi-plugin-oauth2.oauth-access-token')
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
          .service('plugin::strapi-plugin-oauth2.oauth-access-token')
          .revokeTokenByJti(jti, ctx.state.user?.documentId);
        return {
          revoked: ok,
        };
      } catch (err) {
        handleError(ctx, err);
      }
    },

    async token(ctx) {
      try {
        const { grant_type } = ctx.request.body;
        if (grant_type === 'authorization_code') {
          const { code, redirect_uri, code_verifier } = ctx.request.body;
          if (!code || !redirect_uri) {
            throw new ValidationError('invalid_request', {
              error: 'invalid_request',
              message: 'code and redirect_uri are required',
            });
          }
          return await strapi.db.transaction(async () => {
            // 1) consume auth code (ตรวจ: code, redirectUri, PKCE, expiry, usedAt)
            const { client, authorizationUser, scopes } = await strapi
              .service('plugin::strapi-plugin-oauth2.oauth-authorization-code')
              .consumeAuthorizationCode({
                rawCode: code,
                redirectUri: redirect_uri,
                codeVerifier: code_verifier,
              });

            // 2) ถ้า client เป็น confidential → ต้อง auth ด้วย clientSecret อีกชั้น
            if (client.clientType === 'CONFIDENTIAL') {
              let clientId: string | undefined;
              let clientSecret: string | undefined;

              const auth = ctx.request.header.authorization;
              if (auth && auth.startsWith('Basic ')) {
                const creds = Buffer.from(auth.slice('Basic '.length), 'base64').toString();
                [clientId, clientSecret] = creds.split(':');
              } else {
                clientId = ctx.request.body.client_id;
                clientSecret = ctx.request.body.client_secret;
              }
              if (!clientId || !clientSecret) {
                throw new ValidationError('missing_client_credentials', {
                  error: 'invalid_client_credentials',
                });
              }

              const validatedClient = await strapi
                .service('plugin::strapi-plugin-oauth2.oauth-client')
                .validateClientCredentials(clientId, clientSecret);
              // กันกรณี attacker เอา secret ของ client อื่นมาจับคู่ code นี้
              if (!validatedClient || validatedClient.id !== client.id) {
                throw new UnauthorizedError('invalid_client_credentials', {
                  error: 'invalid_client_credentials',
                  message: 'mismatched client credentials',
                });
              }
            }

            const tokenResp = await strapi
              .service('plugin::strapi-plugin-oauth2.oauth-access-token')
              .issueAccessToken({
                grantType: grant_type,
                client,
                userDocumentId: authorizationUser.documentId,
                scope: scopes.join(' '),
              });
            return tokenResp;
          });
        } else if (grant_type === 'client_credentials') {
          throw new ValidationError('grant_type_deprecated', {
            error: 'grant_type_deprecated',
            message: 'client_credentials is no longer supported',
          });
          // return await strapi.db.transaction(async () => {
          //   let clientId, clientSecret;
          //   const auth = ctx.request.header.authorization;
          //   if (auth && auth.startsWith('Basic ')) {
          //     const creds = Buffer.from(auth.slice('Basic '.length), 'base64').toString();
          //     [clientId, clientSecret] = creds.split(':');
          //   } else {
          //     clientId = ctx.request.body.client_id;
          //     clientSecret = ctx.request.body.client_secret;
          //   }
          //   if (!clientId || !clientSecret) {
          //     throw new ValidationError('invalid_client', {
          //       error: 'invalid_client',
          //     });
          //   }

          //   const client = await strapi
          //     .service('plugin::strapi-plugin-oauth2.oauth-client')
          //     .validateClientCredentials(clientId, clientSecret);
          //   if (!client) {
          //     throw new UnauthorizedError('invalid_client_credentials', {
          //       error: 'invalid_client_credentials',
          //     });
          //   }

          //   const scope = (client.scopes || []).join(' ');
          //   const tokenResp = await strapi
          //     .service('plugin::strapi-plugin-oauth2.oauth-access-token')
          //     .issueAccessToken({
          //       grantType: grant_type,
          //       client,
          //       scope,
          //     });
          //   return tokenResp;
          // });
        } else if (grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
          const { assertion } = ctx.request.body;
          if (!assertion) {
            throw new ValidationError('invalid_request', {
              error: 'invalid_request',
              message: 'assertion is required',
            });
          }

          const { client, decoded } = await strapi
            .service('plugin::strapi-plugin-oauth2.oauth-access-token')
            .verifyJWTBearer(assertion);

          if (client.clientType === 'CONFIDENTIAL') {
            let clientId: string | undefined;
            let clientSecret: string | undefined;

            const auth = ctx.request.header.authorization;
            if (auth && auth.startsWith('Basic ')) {
              const creds = Buffer.from(auth.slice('Basic '.length), 'base64').toString();
              [clientId, clientSecret] = creds.split(':');
            } else {
              clientId = ctx.request.body.client_id;
              clientSecret = ctx.request.body.client_secret;
            }
            if (!clientId || !clientSecret) {
              throw new ValidationError('missing_client_credentials', {
                error: 'invalid_client_credentials',
              });
            }

            const validatedClient = await strapi
              .service('plugin::strapi-plugin-oauth2.oauth-client')
              .validateClientCredentials(clientId, clientSecret);
            // กันกรณี attacker เอา secret ของ client อื่นมาจับคู่ assertion นี้
            if (!validatedClient || validatedClient.id !== client.id) {
              throw new UnauthorizedError('invalid_client_credentials', {
                error: 'invalid_client_credentials',
                message: 'mismatched client credentials',
              });
            }
          } else {
            throw new ValidationError('unauthorized_client', {
              error: 'unauthorized_client',
              message: 'only CONFIDENTIAL client is allowed to use this grant type',
            });
          }

          if (!decoded.scope) {
            throw new ValidationError('invalid_scope', {
              error: 'invalid_scope',
              message: 'scope is required in assertion',
            });
          }
          const requestedScopes = decoded.scope.split(' ');

          const globalSettings = await strapi
            .documents('plugin::strapi-plugin-oauth2.oauth-global-setting')
            .findFirst({
              populate: ['scopes'],
            });
          const availableScopes = globalSettings?.scopes?.length
            ? globalSettings.scopes.map((s) => s.name)
            : [];
          if (!availableScopes.length) {
            throw new ValidationError('invalid_scope', {
              error: 'invalid_scope',
              message: 'no available scopes defined',
            });
          }

          // check requested scopes are subset of available scopes
          for (const s of requestedScopes) {
            if (!availableScopes.includes(s)) {
              throw new ValidationError('invalid_scope', {
                error: 'invalid_scope',
                message: `scope ${s} is not allowed for this client`,
              });
            }
          }

          const tokenResp = await strapi
            .service('plugin::strapi-plugin-oauth2.oauth-access-token')
            .issueAccessToken({
              grantType: grant_type,
              client,
              userDocumentId: client.user?.documentId,
              scope: requestedScopes.join(' '),
            });
          return tokenResp;
        } else {
          throw new ValidationError('unsupported_grantType', {
            error: 'unsupported_grantType',
          });
        }
      } catch (err) {
        handleError(ctx, err);
      }
    },
  })
);
