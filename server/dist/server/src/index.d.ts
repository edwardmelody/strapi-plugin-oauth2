declare const _default: {
    register: ({ strapi }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => void;
    bootstrap: ({ strapi }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => Promise<void>;
    destroy: ({ strapi }: {
        strapi: import("@strapi/types/dist/core").Strapi;
    }) => void;
    config: ({ env }: {
        env: any;
    }) => {
        default: {};
        validator(): void;
    };
    controllers: {
        oauth: ({ strapi }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => {
            getAvailableScopes(ctx: any): Promise<void>;
        };
        'oauth-access-token': ({ strapi, }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => {
            introspect: (ctx: import("koa").Context) => Promise<any>;
            revoke: (ctx: import("koa").Context) => Promise<{
                revoked: any;
            }>;
            token: (ctx: import("koa").Context) => Promise<any>;
        } & import("@strapi/types/dist/core/core-api/controller").Base;
        'oauth-client': ({ strapi, }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => Partial<import("@strapi/types/dist/core/core-api/controller").Base> & import("@strapi/types/dist/core/core-api/controller").Generic & import("@strapi/types/dist/core/core-api/controller").Base;
        'oauth-global-setting': ({ strapi, }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => Partial<import("@strapi/types/dist/core/core-api/controller").Base> & import("@strapi/types/dist/core/core-api/controller").Generic & import("@strapi/types/dist/core/core-api/controller").Base;
        'oauth-authorization-code': ({ strapi, }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => {
            authorize: (ctx: import("koa").Context) => Promise<{
                redirectUri: string;
            }>;
            introspect: (ctx: import("koa").Context) => Promise<any>;
            revoke: (ctx: import("koa").Context) => Promise<{
                revoked: any;
            }>;
        } & import("@strapi/types/dist/core/core-api/controller").Base;
    };
    routes: {
        'content-api': {
            type: string;
            routes: {
                method: string;
                path: string;
                handler: string;
                config: {
                    policies: any[];
                    middlewares: any[];
                };
            }[];
        };
        admin: {
            type: string;
            routes: {
                method: string;
                path: string;
                handler: string;
                config: {
                    policies: {
                        name: string;
                        config: {
                            actions: string[];
                        };
                    }[];
                };
            }[];
        };
    };
    services: {
        'oauth-access-token': ({ strapi, }: {
            strapi: import("@strapi/types/dist/core").Strapi;
        }) => {
            issueAccessToken: ({ grantType, client, userDocumentId, scope }: import("./types/oauth").IssueAccessTokenParams) => Promise<{
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
                decoded: import("./types/oauth").OAuthJwtPayload;
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
    contentTypes: {
        'oauth-access-token': {
            schema: {
                kind: string;
                collectionName: string;
                info: {
                    singularName: string;
                    pluralName: string;
                    displayName: string;
                };
                options: {
                    draftAndPublish: boolean;
                };
                pluginOptions: {};
                attributes: {
                    accessToken: {
                        type: string;
                        required: boolean;
                        private: boolean;
                    };
                    jti: {
                        type: string;
                        required: boolean;
                        unique: boolean;
                    };
                    client: {
                        type: string;
                        relation: string;
                        target: string;
                        required: boolean;
                    };
                    expiresAt: {
                        type: string;
                        required: boolean;
                    };
                    scope: {
                        type: string;
                    };
                    revokedAt: {
                        type: string;
                    };
                    grantType: {
                        type: string;
                        required: boolean;
                        enum: string[];
                    };
                    user: {
                        type: string;
                        relation: string;
                        target: string;
                        required: boolean;
                    };
                };
            };
        };
        'oauth-client': {
            schema: {
                kind: string;
                collectionName: string;
                info: {
                    singularName: string;
                    pluralName: string;
                    displayName: string;
                };
                options: {
                    draftAndPublish: boolean;
                };
                pluginOptions: {};
                attributes: {
                    clientId: {
                        type: string;
                        unique: boolean;
                    };
                    clientSecretHash: {
                        type: string;
                        private: boolean;
                    };
                    jwtAlg: {
                        type: string;
                        required: boolean;
                        enum: string[];
                    };
                    publicKey: {
                        type: string;
                    };
                    name: {
                        type: string;
                        required: boolean;
                    };
                    scopes: {
                        type: string;
                    };
                    redirectUris: {
                        type: string;
                    };
                    active: {
                        type: string;
                        default: boolean;
                    };
                    meta: {
                        type: string;
                    };
                    user: {
                        type: string;
                        relation: string;
                        target: string;
                    };
                    clientType: {
                        type: string;
                        required: boolean;
                        enum: string[];
                    };
                    createdType: {
                        type: string;
                        required: boolean;
                        enum: string[];
                    };
                };
            };
        };
        'oauth-user': {
            schema: {
                kind: string;
                collectionName: string;
                info: {
                    singularName: string;
                    pluralName: string;
                    displayName: string;
                };
                options: {
                    draftAndPublish: boolean;
                };
                pluginOptions: {};
                attributes: {
                    userDocumentId: {
                        type: string;
                        required: boolean;
                    };
                    clientId: {
                        type: string;
                        required: boolean;
                    };
                    scopes: {
                        type: string;
                    };
                    apiTokenId: {
                        type: string;
                        min: number;
                        required: boolean;
                    };
                    apiTokenAccessKey: {
                        type: string;
                        required: boolean;
                        private: boolean;
                        searchable: boolean;
                    };
                    client: {
                        type: string;
                        relation: string;
                        target: string;
                    };
                    user: {
                        type: string;
                        relation: string;
                        target: string;
                    };
                };
            };
        };
        'oauth-global-setting': {
            schema: {
                kind: string;
                collectionName: string;
                info: {
                    singularName: string;
                    pluralName: string;
                    displayName: string;
                };
                options: {
                    draftAndPublish: boolean;
                };
                pluginOptions: {};
                attributes: {
                    systemAccessKey: {
                        type: string;
                        required: boolean;
                        private: boolean;
                        searchable: boolean;
                    };
                    scopes: {
                        type: string;
                    };
                };
            };
        };
        'oauth-authorization-code': {
            schema: {
                kind: string;
                collectionName: string;
                info: {
                    singularName: string;
                    pluralName: string;
                    displayName: string;
                };
                options: {
                    draftAndPublish: boolean;
                };
                pluginOptions: {};
                attributes: {
                    codeHash: {
                        type: string;
                        private: boolean;
                    };
                    client: {
                        type: string;
                        relation: string;
                        target: string;
                    };
                    user: {
                        type: string;
                        relation: string;
                        target: string;
                    };
                    scopes: {
                        type: string;
                    };
                    redirectUri: {
                        type: string;
                        required: boolean;
                    };
                    codeChallenge: {
                        type: string;
                    };
                    codeChallengeMethod: {
                        type: string;
                    };
                    expiresAt: {
                        type: string;
                        required: boolean;
                    };
                    usedAt: {
                        type: string;
                    };
                    meta: {
                        type: string;
                    };
                };
            };
        };
    };
    policies: {};
    middlewares: {
        'oauth-verify-token': () => (ctx: import("koa").Context, next: import("koa").Next) => Promise<any>;
    };
};
export default _default;
