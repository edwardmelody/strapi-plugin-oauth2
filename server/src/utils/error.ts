import { Context } from 'koa';
import utils from '@strapi/utils';
const { ValidationError, NotFoundError, UnauthorizedError } = utils.errors;

export const handleError = (ctx: Context, error: any) => {
  let title = 'other error';
  let details = {
    code: 9999,
    message: 'other error',
  };
  if (error.details) {
    title = error.message ? error.message : title;
    details = error.details;
  }

  if (error instanceof NotFoundError) {
    ctx.notFound(title, details);
  } else if (error instanceof ValidationError) {
    ctx.badRequest(title, details);
  } else if (error instanceof UnauthorizedError) {
    ctx.unauthorized(title, details);
  } else {
    ctx.internalServerError(title, details);
  }

  // log outgoing response error
  strapi.log.error(`http: ${ctx.request.method} ${ctx.request.url}`);
  if (ctx.request.body && Object.keys(ctx.request.body).length > 0) {
    strapi.log.error(`body: ${JSON.stringify(ctx.request.body)}`);
  }
  strapi.log.error(
    `error: ${JSON.stringify({
      title,
      details,
    })}`
  );
};
