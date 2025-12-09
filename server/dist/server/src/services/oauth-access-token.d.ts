import type { IssueAccessTokenParams, OAuthJwtPayload } from '../types/oauth';
declare const _default: ({ strapi, }: {
    strapi: import("@strapi/types/dist/core").Strapi;
}) => {
    issueAccessToken: ({ grantType, client, userDocumentId, scope }: IssueAccessTokenParams) => Promise<{
        accessToken: any;
        tokenType: string;
        expiresIn: number;
        scope: string;
    }>;
    introspectByToken: (token: string, userDocumentId: string) => Promise<false | {
        active: boolean;
        grantType?: undefined;
        clientId?: undefined;
        userId?: undefined;
        audience?: undefined;
        scope?: undefined;
        exp?: undefined;
        iat?: undefined;
        jti?: undefined;
    } | {
        active: boolean;
        grantType: any;
        clientId: string;
        userId: string;
        audience: string | string[];
        scope: string;
        exp: number;
        iat: number;
        jti: string;
    }>;
    revokeTokenByJti: (jti: string, userDocumentId: string) => Promise<boolean>;
    verifyJWTBearer: (assertion: string) => Promise<{
        client: import("@strapi/types/dist/modules/documents").AnyDocument;
        decoded: OAuthJwtPayload;
    }>;
} & import("@strapi/types/dist/core/core-api/service").Base;
export default _default;
