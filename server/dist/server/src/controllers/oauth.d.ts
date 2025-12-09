import type { Core } from '@strapi/strapi';
declare const controller: ({ strapi }: {
    strapi: Core.Strapi;
}) => {
    getAvailableScopes(ctx: any): Promise<void>;
};
export default controller;
