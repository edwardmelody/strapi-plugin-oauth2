declare const _default: {
    'oauth-access-token': ({ strapi, }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => {
        issueAccessToken: ({ grantType, client, userDocumentId, scope }: import("../types/oauth").IssueAccessTokenParams) => Promise<{
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
            decoded: import("../types/oauth").OAuthJwtPayload;
        }>;
    } & import("@strapi/types/dist/core/core-api/service").Base;
    'oauth-client': ({ strapi, }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => {
        findOne: (documentId: string, params: any) => Promise<any>;
        create: (params: any) => Promise<{
            clientSecret: string;
            privateKey: string;
            documentId: string;
            id: number;
        }>;
        rotateClientSecret: (documentId: string, userDocumentId: string) => Promise<{
            clientSecret: string;
            documentId: string;
            id: number;
        }>;
        update: (documentId: any, params: any) => Promise<any>;
        delete: (documentId: any, params: any) => Promise<void>;
        validateClientCredentials: (clientId: string, clientSecret: string) => Promise<import("@strapi/types/dist/modules/documents").AnyDocument>;
        generateKeyPair: (clientDocumentId: string) => Promise<{
            privateKey: string;
            documentId: string;
            id: number;
        }>;
    } & import("@strapi/types/dist/core/core-api/service").Base;
    'oauth-global-setting': ({ strapi, }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => Partial<import("@strapi/types/dist/core/core-api/service").Base> & import("@strapi/types/dist/core/core-api/service").Generic & import("@strapi/types/dist/core/core-api/service").Base;
    'oauth-authorization-code': ({ strapi, }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => {
        createAuthorizationCode: ({ clientId, userDocumentId, redirectUri, scopes, codeChallenge, codeChallengeMethod, }: {
            clientId: any;
            userDocumentId: any;
            redirectUri: any;
            scopes: any;
            codeChallenge: any;
            codeChallengeMethod: any;
        }) => Promise<string>;
        consumeAuthorizationCode: ({ rawCode, redirectUri, codeVerifier }: {
            rawCode: any;
            redirectUri: any;
            codeVerifier?: any;
        }) => Promise<{
            client: any;
            authorizationUser: any;
            scopes: any;
        }>;
    } & import("@strapi/types/dist/core/core-api/service").Base;
};
export default _default;
