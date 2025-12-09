import { JwtPayload } from 'jsonwebtoken';

export interface CreateClientParams {
  userDocumentId: string;
  clientType: 'CONFIDENTIAL' | 'PUBLIC';
  name: string;
  scopes?: string[];
  meta?: Record<string, any>;
  createdType: 'USER' | 'BACK_OFFICE';
}

export interface IssueAccessTokenParams {
  client: any;
  userDocumentId: string;
  scope?: string;
  audience: string;
  grantType:
    | 'authorization_code'
    | 'client_credentials'
    | 'urn:ietf:params:oauth:grant-type:jwt-bearer';
}

export interface OAuthJwtPayload extends JwtPayload {
  sub: string;
  scope: string;
  jti: string;
}
