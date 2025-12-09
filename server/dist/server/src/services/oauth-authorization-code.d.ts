declare const _default: ({ strapi, }: {
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
export default _default;
