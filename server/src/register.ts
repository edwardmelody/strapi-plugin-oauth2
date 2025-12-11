import type { Core } from '@strapi/strapi';

import components from './components';

const register = ({ strapi }: { strapi: Core.Strapi }) => {
  // register phase
  for (const componentKey of Object.keys(components)) {
    strapi.components[componentKey] = components[componentKey];
  }
};

export default register;
