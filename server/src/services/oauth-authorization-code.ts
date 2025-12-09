import { factories } from '@strapi/strapi';

import { generateAuthCode, getOAuthConfig, hashValue, verifyPkce } from '../utils/oauth-utils';

import utils from '@strapi/utils';
const { ValidationError, NotFoundError } = utils.errors;

export default factories.createCoreService(
  'plugin::oauth2.oauth-authorization-code',
  ({ strapi }) => ({
    async createAuthorizationCode({
      clientId,
      userDocumentId,
      redirectUri,
      scopes,
      codeChallenge,
      codeChallengeMethod,
    }) {
      const { authCodeTtlSeconds } = getOAuthConfig();

      // find client
      const oauthClient = await strapi.documents('plugin::oauth2.oauth-client').findFirst({
        filters: {
          clientId,
        },
        populate: {
          user: true,
        },
      });
      if (!oauthClient) throw new NotFoundError('invalid_client');
      if (oauthClient.clientType === 'PUBLIC') {
        if (!codeChallenge) {
          throw new ValidationError('code_challenge_required_for_public_client');
        } else if (!codeChallengeMethod) {
          throw new ValidationError('code_challenge_method_required_for_public_client');
        }
      }

      // validate redirectUri matches
      if (!oauthClient.redirectUris.includes(redirectUri)) {
        throw new ValidationError('redirect_uri_mismatch');
      }

      let availableScopes = { ...oauthClient.scopes };
      if (oauthClient.createdType === 'USER') {
        const globalSettings = await strapi
          .documents('plugin::oauth2.oauth-global-setting')
          .findFirst();
        availableScopes = globalSettings?.scopes || {};

        if (!availableScopes?.length) {
          throw new ValidationError('no_available_scopes_defined');
        }
      }
      // check requested scopes are subset of available scopes
      for (const s of scopes) {
        if (!availableScopes.includes(s)) {
          throw new ValidationError(`invalid_scope: ${s}`);
        }
      }

      // build raw code
      const rawCode = generateAuthCode(32);
      const codeHash = hashValue(rawCode);
      const expiresAt = new Date(Date.now() + authCodeTtlSeconds * 1000).toISOString();

      await strapi.db.transaction(async () => {
        // create record
        await strapi.documents('plugin::oauth2.oauth-authorization-code').create({
          data: {
            codeHash,
            client: oauthClient.documentId,
            user: userDocumentId,
            scopes,
            redirectUri,
            codeChallenge,
            codeChallengeMethod,
            expiresAt,
          },
        });

        // create API Token for this authorization code
        const tokenName = `OAuth2_${oauthClient.clientId}_${userDocumentId}`;
        const tokenExists = await strapi.service('admin::api-token').exists({
          name: tokenName,
        });
        let apiTokenId;
        let apiTokenAccessKey;
        if (!tokenExists) {
          const result = await strapi.service('admin::api-token').create({
            name: tokenName,
            description: `System token for Strapi OAuth2 plugin to access internal APIs. Created to client_id: ${oauthClient.clientId} and user_id: ${userDocumentId}`,
            type: 'custom',
            lifespan: null,
            permissions: scopes,
          });
          apiTokenId = result.id;
          apiTokenAccessKey = result.accessKey;
        }

        const userClient = await strapi.documents('plugin::oauth2.oauth-user').findFirst({
          filters: {
            userDocumentId: userDocumentId,
            clientId: oauthClient.clientId,
          },
        });
        if (!userClient) {
          // create user-client record
          await strapi.documents('plugin::oauth2.oauth-user').create({
            data: {
              userDocumentId: userDocumentId,
              clientId: oauthClient.clientId,
              client: oauthClient.documentId,
              user: userDocumentId,
              scopes,
              apiTokenId,
              apiTokenAccessKey,
            } as any,
          });
        } else {
          // update user's granted scopes
          const newData = {
            scopes,
          };
          if (apiTokenId && apiTokenAccessKey) {
            newData['apiTokenId'] = apiTokenId;
            newData['apiTokenAccessKey'] = apiTokenAccessKey;
          } else {
            // update api token permissions if scopes changed
            await strapi.service('admin::api-token').update(userClient.apiTokenId, {
              permissions: scopes,
            });
          }
          await strapi.documents('plugin::oauth2.oauth-user').update({
            documentId: userClient.documentId,
            data: newData as any,
          });
        }
      });

      return rawCode; // return raw code to redirect user
    },
    async consumeAuthorizationCode({ rawCode, redirectUri, codeVerifier = null }) {
      const codeHash = hashValue(rawCode);
      // find row (and ensure not used and not expired)
      const rec = await strapi.documents('plugin::oauth2.oauth-authorization-code').findFirst({
        filters: {
          codeHash,
        },
        populate: {
          client: {
            populate: {
              user: true,
            },
          },
          user: true,
        },
        sort: { createdAt: 'desc' },
      });
      if (!rec) throw new NotFoundError('invalid_grant');

      if (rec.usedAt) throw new ValidationError('invalid_grant_already_used');
      if (new Date(rec.expiresAt) <= new Date()) throw new ValidationError('invalid_grant_expired');

      // validate redirectUri matches
      if (rec.redirectUri !== redirectUri) throw new ValidationError('redirect_uri_mismatch');

      if (rec.client.clientType === 'PUBLIC') {
        if (!codeVerifier) {
          throw new ValidationError('code_verifier_required_for_public_client');
        } else if (!rec.codeChallenge) {
          throw new ValidationError('code_challenge_not_found_for_public_client');
        } else if (!rec.codeChallengeMethod) {
          throw new ValidationError('code_challenge_method_not_found_for_public_client');
        }
      }

      // validate PKCE if present
      if (rec.codeChallenge && rec.codeChallengeMethod) {
        if (!codeVerifier) throw new ValidationError('code_verifier_required');
        const ok = verifyPkce(codeVerifier, rec.codeChallenge, rec.codeChallengeMethod);
        if (!ok) throw new ValidationError('invalid_code_verifier');
      }

      // mark used
      await strapi.documents('plugin::oauth2.oauth-authorization-code').update({
        documentId: rec.documentId,
        data: {
          usedAt: new Date().toISOString(),
        } as any,
      });

      // return client and user and scopes (for issuing token)
      return {
        client: rec.client,
        authorizationUser: rec.user,
        scopes: rec.scopes,
      };
    },
  })
);
