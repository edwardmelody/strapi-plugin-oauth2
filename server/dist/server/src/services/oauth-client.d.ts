declare const _default: ({ strapi, }: {
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
export default _default;
