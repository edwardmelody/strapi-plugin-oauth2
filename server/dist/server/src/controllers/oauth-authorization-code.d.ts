declare const _default: ({ strapi, }: {
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
export default _default;
