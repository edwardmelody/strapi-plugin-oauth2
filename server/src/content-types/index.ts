import oauthAccessToken from './oauth-access-token/schema.json';
import oauthClient from './oauth-client/schema.json';
import oauthUser from './oauth-user/schema.json';
import oauthGlobalSetting from './oauth-global-setting/schema.json';
import oauthAuthorizationCode from './oauth-authorization-code/schema.json';

export default {
  'oauth-access-token': {
    schema: oauthAccessToken,
  },
  'oauth-client': {
    schema: oauthClient,
  },
  'oauth-user': {
    schema: oauthUser,
  },
  'oauth-global-setting': {
    schema: oauthGlobalSetting,
  },
  'oauth-authorization-code': {
    schema: oauthAuthorizationCode,
  },
};
