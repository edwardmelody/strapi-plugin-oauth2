import { factories } from '@strapi/strapi';

import { handleError } from '../utils/error';

import _ from 'lodash';

import utils from '@strapi/utils';
const { NotFoundError, ValidationError } = utils.errors;

export default factories.createCoreController('plugin::oauth2.oauth-client', ({ strapi }) => ({
  async find(ctx) {
    const filters: any = ctx.query?.filters || {};
    if (ctx.state.user && ctx.state.auth?.strategy?.name !== 'admin') {
      _.set(filters, 'user.documentId', ctx.state.user.documentId);
    }
    return await super.find({ ...ctx, query: { ...ctx.query, filters } });
  },
  async findOne(ctx) {
    const filters: any = ctx.query?.filters || {};
    if (ctx.state.user && ctx.state.auth?.strategy?.name !== 'admin') {
      _.set(filters, 'user.documentId', ctx.state.user.documentId);
    }
    return await super.findOne({ ...ctx, query: { ...ctx.query, filters } });
  },
  async rotateSecret(ctx) {
    try {
      const { documentId } = ctx.params;

      const entity = await strapi
        .service('plugin::oauth2.oauth-client')
        .rotateClientSecret(documentId, ctx.state.user?.documentId);

      const sanitizedOutput = await this.sanitizeOutput(entity, ctx);
      return this.transformResponse(sanitizedOutput);
    } catch (err) {
      handleError(ctx, err);
    }
  },
  async findOneByClientId(ctx) {
    try {
      const { clientId } = ctx.params;

      const scope = ctx.query?.scope as string;

      if (!scope) {
        throw new ValidationError('scope is required');
      }
      const scopes = scope.split(',');

      const filters = {
        clientId,
      };
      if (ctx.state.user) {
        _.set(filters, 'user.documentId', ctx.state.user.documentId);
      }

      const client = await strapi.documents('plugin::oauth2.oauth-client').findFirst({
        filters,
      });
      if (!client) throw new NotFoundError('client_not_found');
      let availableScopes = { ...client.scopes };
      if (client.createdType === 'USER') {
        const globalSettings = await strapi
          .documents('plugin::oauth2.oauth-global-setting')
          .findFirst();
        availableScopes = globalSettings?.scopes || {};

        if (!availableScopes?.length) {
          throw new ValidationError('no_available_scopes_defined');
        }
      }

      const clientUser = await strapi.documents('plugin::oauth2.oauth-user').findFirst({
        filters: {
          userDocumentId: ctx.state.user?.documentId,
          clientId: client.clientId,
        },
      });

      // check requested scopes are subset of available scopes
      for (const s of scopes) {
        if (!availableScopes.includes(s)) {
          throw new ValidationError(`invalid_scope: ${s}`);
        }
      }

      return {
        documentId: client.documentId,
        clientId: client.clientId,
        userId: client.user?.documentId,
        clientType: client.clientType,
        name: client.name,
        scopes: scopes,
        grantedScopes: clientUser?.scopes || [],
        redirectUris: client.redirectUris,
        meta: client.meta,
      };
    } catch (err) {
      handleError(ctx, err);
    }
  },

  async generateKeyPair(ctx) {
    try {
      const { documentId } = ctx.params;
      const entity = await strapi
        .service('plugin::oauth2.oauth-client')
        .generateKeyPair(documentId);
      const sanitizedOutput = await this.sanitizeOutput(entity, ctx);

      return this.transformResponse(sanitizedOutput);
    } catch (err) {
      handleError(ctx, err);
    }
  },

  async delete(ctx) {
    try {
      return await super.delete(ctx);
    } catch (err) {
      handleError(ctx, err);
    }
  },
}));
