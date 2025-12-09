import oauth from './oauth';
import oauthAccessToken from './oauth-access-token';
import oauthClient from './oauth-client';
import oauthGlobalSetting from './oauth-global-setting';
import oauthAuthorizationCode from './oauth-authorization-code';

export default {
  oauth,
  'oauth-access-token': oauthAccessToken,
  'oauth-client': oauthClient,
  'oauth-global-setting': oauthGlobalSetting,
  'oauth-authorization-code': oauthAuthorizationCode,
};
