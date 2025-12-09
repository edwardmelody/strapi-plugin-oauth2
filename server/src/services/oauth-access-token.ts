import { factories } from '@strapi/strapi';
import { generateJti, getOAuthConfig, signJWT, verifyJWT } from '../utils/oauth-utils';
import type { IssueAccessTokenParams, OAuthJwtPayload } from '../types/oauth';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';

import utils from '@strapi/utils';
const { ValidationError, NotFoundError } = utils.errors;

export default factories.createCoreService('plugin::oauth2.oauth-access-token', ({ strapi }) => ({
  // issue token (JWT) and store record
  async issueAccessToken({ grantType, client, userDocumentId, scope }: IssueAccessTokenParams) {
    const { accessTokenTTL, audience } = getOAuthConfig();

    const now = Math.floor(Date.now() / 1000);
    const jti = generateJti();
    const payload = {
      iss: userDocumentId,
      sub: client.clientId,
      aud: audience,
      iat: now,
      jti,
      scope,
    };

    const token = signJWT(payload, { expiresIn: accessTokenTTL });
    const expiresAt = new Date(Date.now() + accessTokenTTL * 1000);

    // store token record — store raw token (private) or hash depending privacy choice
    const entity = await strapi.documents('plugin::oauth2.oauth-access-token').create({
      data: {
        accessToken: token,
        jti,
        client: client.documentId,
        expiresAt: expiresAt.toISOString(),
        scope: payload.scope,
        user: userDocumentId,
        grantType,
      },
      populate: {
        user: true,
      },
    });

    return {
      accessToken: entity.accessToken,
      tokenType: 'Bearer',
      expiresIn: accessTokenTTL,
      scope: payload.scope,
    };
  },

  // introspect by token or jti
  async introspectByToken(token: string, userDocumentId: string) {
    // verify signature
    const res = verifyJWT(token);
    if (!res.ok) return { active: false };
    const decoded = res.decoded as OAuthJwtPayload;
    if (typeof decoded === 'string') return { active: false };
    // Find token record and check revoked
    const rec = await strapi.documents('plugin::oauth2.oauth-access-token').findFirst({
      filters: { jti: decoded.jti },
    });
    if (!rec) return { active: false };
    const ctx = strapi.requestContext.get();
    if (
      ctx.state.auth?.strategy?.name !== 'admin' &&
      userDocumentId &&
      rec.user.documentId !== userDocumentId
    ) {
      return false;
    }
    if (rec.revokedAt) return { active: false };
    if (new Date(rec.expiresAt) <= new Date()) return { active: false };
    return {
      active: true,
      grantType: rec.grantType,
      clientId: decoded.sub,
      userId: decoded.iss,
      audience: decoded.aud,
      scope: decoded.scope,
      exp: decoded.exp,
      iat: decoded.iat,
      jti: decoded.jti,
    };
  },

  async revokeTokenByJti(jti: string, userDocumentId: string) {
    const rec = await strapi.documents('plugin::oauth2.oauth-access-token').findFirst({
      filters: { jti },
      populate: {
        user: true,
      },
    });
    if (!rec) return false;

    const ctx = strapi.requestContext.get();
    if (
      ctx.state.auth?.strategy?.name !== 'admin' &&
      userDocumentId &&
      rec.user.documentId !== userDocumentId
    ) {
      return false;
    }
    await strapi.documents('plugin::oauth2.oauth-access-token').update({
      documentId: rec.documentId,
      data: {
        revokedAt: new Date().toISOString(),
      } as any,
    });
    return true;
  },

  async verifyJWTBearer(assertion: string) {
    // 1) decode แบบไม่ verify ก่อน เพื่อดู iss / sub
    let decoded: any;
    try {
      decoded = jwt.decode(assertion, { complete: true });
    } catch (err) {
      throw new ValidationError('invalid_request', {
        error: 'invalid_request',
        message: 'invalid JWT format',
      });
    }

    if (!decoded || typeof decoded !== 'object') {
      throw new ValidationError('invalid_request', {
        error: 'invalid_request',
        message: 'invalid JWT',
      });
    }

    const payload = decoded.payload || {};
    const clientId = payload.sub;

    if (!clientId) {
      throw new ValidationError('invalid_client', {
        error: 'invalid_client',
        message: 'iss or sub is required',
      });
    }

    // 2) หา client จาก DB
    const client = await strapi.documents('plugin::oauth2.oauth-client').findFirst({
      filters: {
        clientId,
      },
      populate: {
        user: true,
      },
    });

    if (!client) {
      throw new ValidationError('invalid_client', {
        error: 'invalid_client',
      });
    }

    if (!client.publicKey || client.jwtAlg !== 'RS256') {
      throw new ValidationError('invalid_client', {
        error: 'invalid_client',
        message: 'client does not support jwt-bearer',
      });
    }

    // 3) verify JWT ด้วย RS256 + secret ของ client
    const res: any = verifyJWT(assertion, {
      jwtAlgOverride: 'RS256',
      verifyKeyOverride: client.publicKey,
    });
    if (!res.ok) {
      throw new ValidationError('invalid_grant', {
        error: 'invalid_grant',
        message: res.err.message || 'invalid or expired assertion',
      });
    }
    const verified = res.decoded as OAuthJwtPayload;

    // 4) เช็ค claims จุดสำคัญ
    if (verified.iss !== client.user.documentId) {
      throw new ValidationError('invalid_grant', {
        error: 'invalid_grant',
        message: 'user mismatch',
      });
    }

    const { audience, maxAssertionTtl } = getOAuthConfig();
    if (verified.aud !== audience) {
      throw new ValidationError('invalid_grant', {
        error: 'invalid_grant',
        message: 'audience mismatch',
      });
    }

    if (typeof verified.iat === 'number' && typeof verified.exp === 'number') {
      const ttl = verified.exp - verified.iat;
      if (ttl > maxAssertionTtl) {
        throw new ValidationError('invalid_grant', {
          error: 'invalid_grant',
          message: 'assertion lifetime too long',
        });
      }
    }

    return {
      client,
      decoded: verified,
    };
  },
}));
