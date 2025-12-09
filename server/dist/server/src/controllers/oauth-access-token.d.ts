declare const _default: ({ strapi, }: {
    strapi: import("@strapi/types/dist/core").Strapi;
}) => {
    introspect: (ctx: import("koa").Context) => Promise<any>;
    revoke: (ctx: import("koa").Context) => Promise<{
        revoked: any;
    }>;
    token: (ctx: import("koa").Context) => Promise<any>;
} & import("@strapi/types/dist/core/core-api/controller").Base;
export default _default;
