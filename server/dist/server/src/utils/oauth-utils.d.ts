import jwt, { JwtPayload } from 'jsonwebtoken';
declare function getOAuthConfig(): {
    jwtAlg: jwt.Algorithm;
    jwtSignKey: jwt.Secret;
    accessTokenTTL: number;
    jwtPublicKey: jwt.Secret;
    jwtPrivateKey: jwt.Secret;
    audience: string;
    authCodeTtlSeconds: number;
    loginUrl: string;
    maxAssertionTtl: number;
    jwtRS256Bits: number;
};
declare function hashSecret(secret: string): Promise<string>;
declare function verifySecret(secret: string, hash: string): Promise<boolean>;
declare function generateClientId(): string;
declare function generateRawSecret(bytes?: number): string;
declare function signJWT(payload: string | object | Buffer, opts?: {
    expiresIn?: number | string;
}): string;
declare function verifyJWT(token: string, { jwtAlgOverride, verifyKeyOverride, }?: {
    jwtAlgOverride?: jwt.Algorithm;
    verifyKeyOverride?: jwt.Secret;
}): {
    ok: true;
    decoded: string | JwtPayload;
} | {
    ok: false;
    err: any;
};
declare function generateJti(): string;
declare function generateAuthCode(bytes?: number): string;
declare function hashValue(value: string): string;
declare function verifyPkce(codeVerifier: string, codeChallenge: string, method?: string): boolean;
declare function generateRSAKeyPair(): {
    publicKey: string;
    privateKey: string;
};
export { getOAuthConfig, hashSecret, verifySecret, generateClientId, generateRawSecret, signJWT, verifyJWT, generateJti, generateAuthCode, hashValue, verifyPkce, generateRSAKeyPair, };
