import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';

function getOAuthConfig() {
  const jwtAlg = strapi.plugin('strapi-plugin-oauth2').config('jwtAlg') || 'HS256';
  const jwtSignKey = strapi.plugin('strapi-plugin-oauth2').config('jwtSignKey');
  const accessTokenTTL = strapi.plugin('strapi-plugin-oauth2').config('accessTokenTTL') || 3600;
  const audience = strapi.plugin('strapi-plugin-oauth2').config('audience');
  const authCodeTtlSeconds =
    strapi.plugin('strapi-plugin-oauth2').config('authCodeTtlSeconds') || 300;
  const callbackUrl = strapi.plugin('strapi-plugin-oauth2').config('callbackUrl');
  const maxAssertionTtl = strapi.plugin('strapi-plugin-oauth2').config('maxAssertionTtl') || 300;
  let jwtPublicKeyPath: string =
    strapi.plugin('strapi-plugin-oauth2').config('jwtPublicKey') || './assets/oauth2/public.key';
  let jwtPrivateKeyPath: string =
    strapi.plugin('strapi-plugin-oauth2').config('jwtPrivateKey') || './assets/oauth2/private.key';
  const jwtRS256Bits = strapi.plugin('strapi-plugin-oauth2').config('jwtRS256Bits') || 2048;

  jwtPublicKeyPath = path.join(process.cwd(), jwtPublicKeyPath);
  jwtPrivateKeyPath = path.join(process.cwd(), jwtPrivateKeyPath);
  if (jwtAlg === 'RS256' && !fs.existsSync(jwtPublicKeyPath)) {
    throw new Error(`OAuth2 plugin: JWT public key file not found at path: ${jwtPublicKeyPath}`);
  } else if (jwtAlg === 'RS256' && !fs.existsSync(jwtPrivateKeyPath)) {
    throw new Error(`OAuth2 plugin: JWT private key file not found at path: ${jwtPrivateKeyPath}`);
  }

  const jwtPublicKey = fs.readFileSync(jwtPublicKeyPath, 'utf8');
  const jwtPrivateKey = fs.readFileSync(jwtPrivateKeyPath, 'utf8');

  return {
    jwtAlg: jwtAlg as jwt.Algorithm,
    jwtSignKey: jwtSignKey as jwt.Secret,
    accessTokenTTL: accessTokenTTL as number,
    jwtPublicKey: jwtPublicKey as jwt.Secret,
    jwtPrivateKey: jwtPrivateKey as jwt.Secret,
    audience: audience as string,
    authCodeTtlSeconds: authCodeTtlSeconds as number,
    callbackUrl: callbackUrl as string,
    maxAssertionTtl: maxAssertionTtl as number,
    jwtRS256Bits: jwtRS256Bits as number,
  };
}

async function hashSecret(secret: string): Promise<string> {
  const saltRounds = 12;
  return await bcrypt.hash(secret, saltRounds);
}

async function verifySecret(secret: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(secret, hash);
}

function generateClientId(): string {
  // readable id
  return uuidv4().replace(/-/g, '');
}

function generateRawSecret(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

function signJWT(
  payload: string | object | Buffer,
  opts: { expiresIn?: number | string } = {}
): string {
  const { jwtAlg, jwtSignKey, jwtPrivateKey, accessTokenTTL } = getOAuthConfig();

  const signKey = jwtAlg === 'RS256' ? jwtPrivateKey : jwtSignKey;

  const signOpts: SignOptions = {
    algorithm: jwtAlg,
  };
  if (opts.expiresIn !== undefined) {
    signOpts.expiresIn = Number(opts.expiresIn);
  } else {
    signOpts.expiresIn = accessTokenTTL;
  }
  return jwt.sign(payload, signKey, signOpts);
}
function verifyJWT(
  token: string,
  {
    jwtAlgOverride,
    verifyKeyOverride,
  }: { jwtAlgOverride?: jwt.Algorithm; verifyKeyOverride?: jwt.Secret } = {}
): { ok: true; decoded: string | JwtPayload } | { ok: false; err: any } {
  const {
    jwtAlg: _jwtAlg,
    jwtSignKey: _jwtSignKey,
    jwtPublicKey: _jwtPublicKey,
  } = getOAuthConfig();
  const jwtAlg = jwtAlgOverride || _jwtAlg;
  const jwtSignKey = verifyKeyOverride || _jwtSignKey;
  const jwtPublicKey = verifyKeyOverride || _jwtPublicKey;

  const verifyKey = jwtAlg === 'RS256' ? jwtPublicKey : jwtSignKey;
  try {
    const decoded = jwt.verify(token, verifyKey, { algorithms: [jwtAlg] });
    return { ok: true, decoded };
  } catch (err) {
    return { ok: false, err };
  }
}

function generateJti(): string {
  return uuidv4();
}

function generateAuthCode(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex'); // raw code (send to client)
}

function hashValue(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// PKCE verify S256
function verifyPkce(codeVerifier: string, codeChallenge: string, method = 'S256') {
  if (!codeVerifier) return false;
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest();
    const b64 = hash.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return b64 === codeChallenge;
  }
  return false;
}

function generateRSAKeyPair() {
  const { jwtRS256Bits } = getOAuthConfig();

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: jwtRS256Bits,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
  return { publicKey, privateKey };
}

/**
 * Mask a secret string, showing only the last 5 characters
 * Example: "abc123def456" -> "*****f456"
 */
function maskSecret(secret: string, visibleChars: number = 5): string {
  if (!secret || secret.length <= visibleChars) {
    return secret;
  }
  const maskedPart = '*'.repeat(Math.min(secret.length - visibleChars, 20));
  const visiblePart = secret.slice(-visibleChars);
  return maskedPart + visiblePart;
}

/**
 * Mask a private key, showing only header, footer, and last 20 characters of content
 * Example:
 * -----BEGIN PRIVATE KEY-----
 * MIIEvQIBA...last_20_chars
 * -----END PRIVATE KEY-----
 */
function maskPrivateKey(privateKey: string, visibleChars: number = 20): string {
  if (!privateKey) {
    return privateKey;
  }

  const lines = privateKey.split('\n');
  if (lines.length < 3) {
    return privateKey;
  }

  const header = lines[0];
  const footer = lines[lines.length - 1] || lines[lines.length - 2];
  const content = lines.slice(1, -1).join('');

  if (content.length <= visibleChars) {
    return privateKey;
  }

  const visiblePart = content.replace('-----END PRIVATE KEY-----', '').slice(-visibleChars);
  const maskedContent = '...' + visiblePart;

  return `${header}\n${maskedContent}\n${footer}`;
}

export {
  getOAuthConfig,
  hashSecret,
  verifySecret,
  generateClientId,
  generateRawSecret,
  signJWT,
  verifyJWT,
  generateJti,
  generateAuthCode,
  hashValue,
  verifyPkce,
  generateRSAKeyPair,
  maskSecret,
  maskPrivateKey,
};
