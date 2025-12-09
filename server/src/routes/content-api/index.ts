import oauthAccessToken from './oauth-access-token';
import oauthClient from './oauth-client';
import oauthGlobalSetting from './oauth-global-setting';
import oauthAuthorizationCode from './oauth-authorization-code';

export default {
  type: 'content-api',
  routes: [...oauthAccessToken, ...oauthClient, ...oauthGlobalSetting, ...oauthAuthorizationCode],
};
