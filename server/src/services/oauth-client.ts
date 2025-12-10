import { factories } from '@strapi/strapi';

import utils from '@strapi/utils';
import {
  generateClientId,
  generateRawSecret,
  generateRSAKeyPair,
  getOAuthConfig,
  hashSecret,
  verifySecret,
  maskSecret,
  maskPrivateKey,
} from '../utils/oauth-utils';
const { ValidationError, NotFoundError } = utils.errors;

import _ from 'lodash';

export default factories.createCoreService(
  'plugin::strapi-plugin-oauth2.oauth-client',
  ({ strapi }) => ({
    async findOne(documentId: string, params) {
      const ctx = strapi.requestContext.get();
      documentId = documentId || ctx?.params?.documentId;
      if (!documentId) {
        throw new ValidationError('documentId is required');
      }

      params = params || { ...ctx.query };
      return await super.findOne(documentId, params);
    },
    async create(params) {
      const { data } = params;

      const ctx = strapi.requestContext.get();

      if (!ctx?.state.user) {
        throw new ValidationError('user is required');
      }

      const clientId = generateClientId();
      const rawSecret = generateRawSecret(32);
      const secretHash = await hashSecret(rawSecret);
      const { publicKey, privateKey } = generateRSAKeyPair();

      let userDocumentId = data.user;
      const createdType = ctx.state.auth?.strategy?.name === 'admin' ? 'BACK_OFFICE' : 'USER';
      if (createdType === 'USER') {
        userDocumentId = ctx.state.user.documentId;
      }

      const { callbackUrl } = getOAuthConfig();

      if (callbackUrl) {
        data.redirectUris = data.redirectUris || [];
        data.redirectUris.unshift(callbackUrl);
      }

      const entity = await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').create({
        data: {
          ...data,
          clientId,
          clientSecret: maskSecret(rawSecret),
          clientSecretHash: secretHash,
          user: userDocumentId,
          createdType,
          jwtAlg: 'RS256',
          publicKey,
          privateKey: maskPrivateKey(privateKey),
        },
        populate: {
          user: true,
        },
      });

      return {
        ...entity,
        clientSecret: rawSecret,
        privateKey,
      };
    },
    async rotateClientSecret(documentId: string, userDocumentId: string) {
      const ctx = strapi.requestContext.get();

      const client = await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').findFirst({
        filters: { documentId, active: true },
        populate: {
          user: true,
        },
      });
      if (!client) throw new NotFoundError('client_not_found');
      if (
        ctx.state.auth?.strategy?.name !== 'admin' &&
        client.user?.documentId !== userDocumentId
      ) {
        throw new ValidationError('invalid_user');
      }
      const rawSecret = generateRawSecret(32);
      const secretHash = await hashSecret(rawSecret);
      await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').update({
        documentId: client.documentId,
        data: {
          clientSecret: maskSecret(rawSecret),
          clientSecretHash: secretHash,
        } as any,
      });

      return {
        ...client,
        clientSecret: rawSecret,
      };
    },
    async update(documentId, params) {
      const ctx = strapi.requestContext.get();
      documentId = documentId || ctx?.params?.documentId;
      if (!documentId) {
        throw new ValidationError('documentId is required');
      }

      params = params || { ...ctx.query };
      return await super.update(documentId, params);
    },
    async delete(documentId, params) {
      const ctx = strapi.requestContext.get();

      documentId = documentId || ctx?.params?.documentId;
      if (!documentId) {
        throw new ValidationError('documentId is required');
      }

      params = params || { ...ctx.query };
      _.set(params, 'populate.user', true);

      const entity = await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').findOne({
        documentId,
        ...params,
      });
      if (!entity) throw new NotFoundError('client_not_found');
      if (
        ctx.state.auth?.strategy?.name !== 'admin' &&
        entity.user?.documentId !== ctx?.state.user?.documentId
      ) {
        throw new ValidationError('invalid_client_owner');
      }
      if (ctx.state.auth?.strategy?.name !== 'admin' && entity.createdType !== 'USER') {
        throw new ValidationError('cannot_delete_system_client');
      }

      return await strapi.db.transaction(async () => {
        await strapi.db.query('plugin::strapi-plugin-oauth2.oauth-access-token').deleteMany({
          where: {
            client: {
              documentId,
            },
          },
        });

        await strapi.db.query('plugin::strapi-plugin-oauth2.oauth-authorization-code').deleteMany({
          where: {
            client: {
              documentId,
            },
          },
        });

        await strapi.db.query('plugin::strapi-plugin-oauth2.oauth-user').deleteMany({
          where: {
            client: {
              documentId,
            },
          },
        });

        await await super.delete(documentId, params);
      });
    },
    async validateClientCredentials(clientId: string, clientSecret: string) {
      const client = await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').findFirst({
        filters: { clientId, active: true },
      });
      if (!client) return null;
      const ok = await verifySecret(clientSecret, client.clientSecretHash);
      return ok ? client : null;
    },

    async generateKeyPair(clientDocumentId: string) {
      const { publicKey, privateKey } = generateRSAKeyPair();

      const client = await strapi.documents('plugin::strapi-plugin-oauth2.oauth-client').update({
        documentId: clientDocumentId,
        data: {
          jwtAlg: 'RS256',
          publicKey,
          privateKey: maskPrivateKey(privateKey),
        } as any,
        populate: {
          user: true,
        },
      });

      return {
        ...client,
        privateKey,
      };
    },
  })
);
