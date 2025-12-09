declare const _default: {
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
export default _default;
