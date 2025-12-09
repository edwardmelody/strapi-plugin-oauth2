# strapi-plugin-oauth2

A comprehensive OAuth 2.0 server plugin for Strapi that provides secure authentication and authorization with fine-grained scope management based on Strapi's users-permissions actions.

## 🎯 Overview

This plugin is an OAuth 2.0 Authorization Server that works with Strapi with the following capabilities:

- **Scope Management from Users-Permissions**: Select any actions from all users-permissions in your Strapi to define which actions are allowed through the OAuth 2.0 system
- **OAuth Client Management**: Create and manage both Confidential and Public OAuth clients
- **Access Token Issuance**: Issue JWT access tokens with revoke and introspection capabilities
- **Global Scopes System**: Configure system-wide scopes that can be used

## 🚀 Key Features

### 1. Supported Grant Types

The plugin supports the following OAuth 2.0 standard Grant Types:

#### ✅ **Authorization Code Flow** (`authorization_code`)

The most secure standard flow for Web Applications and Mobile Apps

**Features:**

- Supports PKCE (Proof Key for Code Exchange)
  - `code_challenge_method`: `plain` or `S256`
  - Prevents Authorization Code Interception attacks
- Supports both Confidential and Public clients
- Basic Authentication for Confidential clients (`client_id:client_secret`)

**Workflow:**

1. Client requests Authorization Code with `code_challenge` (for PKCE)
2. User logs in and approves access
3. Authorization Server returns Authorization Code
4. Client exchanges Code for Access Token with `code_verifier`
5. Authorization Server validates and issues Access Token

#### ✅ **JWT Bearer Flow** (`urn:ietf:params:oauth:grant-type:jwt-bearer`)

Flow for Service-to-Service Authentication using RS256 JWT assertion

**Features:**

- Uses RSA Key Pair (Public/Private Key)
- Algorithm: **RS256** (RSA Signature with SHA-256)
- No User Interaction required
- Ideal for Backend Services and API Integration

**Workflow:**

1. Client creates JWT assertion and signs with Private Key
2. Sends JWT assertion to Token Endpoint
3. Authorization Server verifies JWT with Public Key
4. Validates requested scopes against Global Scopes
5. Issues Access Token

#### ❌ **Client Credentials Flow** (Deprecated)

This grant type has been deprecated. We recommend using JWT Bearer Flow instead.

### 2. Client Types

#### **Confidential Client**

- Suitable for Server-side Applications
- Requires `client_secret` for authentication
- Supports both Authorization Code and JWT Bearer flows
- Has Basic Authentication (`Authorization: Basic base64(client_id:client_secret)`)

#### **Public Client**

- Suitable for Mobile Apps and Single-Page Applications (SPA)
- **PKCE is mandatory** for security
- No `client_secret`
- Uses only Authorization Code flow with PKCE

### 3. Scope Management

#### **Global Scopes**

Define system-wide scopes available from Strapi users-permissions actions

**Features:**

- Select Actions from all Content Types in Strapi
- Supports CRUD operations (find, findOne, create, update, delete)
- Displayed by Content Type categories
- Used for validating scopes in JWT Bearer Flow

#### **Client Scopes**

Define specific scopes for each OAuth client

**Features:**

- Select subset of scopes from Global Scopes
- Each client has its own specific scopes
- Used for authorizing Access Tokens
- Displayed as scope string (e.g., `api::form.form.find api::form.form.create`)

### 4. Access Token Management

#### **Token Features**

- **JWT Format**: Access tokens เป็น JWT (JSON Web Token)
- **Expiration**: กำหนดเวลาหมดอายุได้ (default: 1 hour)
- **Revocation**: สามารถ revoke tokens ได้ทันที
- **Introspection**: ตรวจสอบสถานะและข้อมูลของ token
- **Tracking**: บันทึกการใช้งาน (created at, used at, expires at, revoked at)

#### **Token Information**

- JTI (JWT ID): Unique identifier
- Client Information
- User Information (ถ้ามี)
- Scopes
- Grant Type ที่ใช้
- Expiration และ Revocation status

### 5. Security Features

#### **PKCE (Proof Key for Code Exchange)**

- **Mandatory** for Public clients
- Supports `plain` and `S256` methods
- Prevents Authorization Code Interception attacks

#### **RSA Key Pairs**

- Automatically generates Key Pair for JWT Bearer clients
- Algorithm: RS256 (2048-bit RSA keys)
- Keys can be rotated

#### **Client Secret Rotation**

- Can rotate `client_secret` at any time
- Old secret is immediately invalidated

#### **Token Security**

- JWT signing with secret key
- Validates token signature on every use
- Checks expiration and revocation

## 📋 Admin Interface

The plugin provides an easy-to-use Admin UI in the Strapi Admin Panel:

### **Global Settings Page**

- Display all Global Scopes
- Edit Global Scopes
- Grouped by Content Type

### **OAuth Clients Management**

- Create new OAuth Client
  - Specify Client Name
  - Select Client Type (Confidential/Public)
  - Select User owner
  - Configure Scopes
  - Configure Redirect URIs
- Display all Clients list
  - Client ID and Name
  - Client Type and Created Type
  - User owner
  - Scopes
  - Status (Active/Inactive)
  - Created and Updated dates
- Edit Client
  - Update Name, Scopes, Redirect URIs
- Rotate Client Secret (for Confidential clients)
- Regenerate RSA Keypair (for JWT Bearer clients)
- Delete Client
- View Access Tokens for each Client

### **Access Tokens Management**

- Display all Access Tokens list
- Filter by Client
- View Token information:
  - Client Name and Client ID
  - Scopes
  - Status (Active/Expired/Revoked)
  - Expiration date
  - Created date
- Revoke Token

### **Pagination**

- Supports pagination for both Clients and Access Tokens
- Select items per page: 10, 25, 50, 100
- Smart pagination display

## 🔧 Installation

### Requirements

- Strapi >= 5.0
- Node.js >= 18.x
- `@strapi/plugin-users-permissions` (included with Strapi)

### Installation

```bash
# Install via npm
npm install strapi-plugin-oauth2

# or yarn
yarn add strapi-plugin-oauth2
```

### Configuration

Add configuration in `config/plugins.js` (or `config/plugins.ts`):

```javascript
module.exports = {
  // ... other plugins
  oauth2: {
    enabled: true,
    config: {
      // JWT Algorithm: 'HS256' (default) or 'RS256'
      jwtAlg: 'HS256',

      // JWT Secret (for HS256)
      jwtSecret: process.env.JWT_SECRET,

      // Access Token Expiration (default: 3600 seconds = 1 hour)
      accessTokenExpiration: 3600,

      // Authorization Code Expiration (default: 300 seconds = 5 minutes)
      authCodeExpiration: 300,
    },
  },
};
```

### Environment Variables

```env
# JWT Secret for signing tokens
JWT_SECRET=your-secret-key-here
```

## 📚 API Endpoints

### Authorization Endpoints

#### **GET** `/oauth2/authorize`

Initiate Authorization Code Flow

**Query Parameters:**

- `client_id` (required): OAuth Client ID
- `redirect_uri` (required): Registered Redirect URI
- `response_type` (required): `code`
- `scope` (optional): Requested scopes (space-separated)
- `state` (optional): State parameter to prevent CSRF
- `code_challenge` (required for Public clients): PKCE code challenge
- `code_challenge_method` (required for Public clients): `plain` or `S256`

**Response:**

- Redirects to login page (if not logged in)
- Shows consent page (approve access)
- Redirects back to `redirect_uri` with `code` and `state`

#### **POST** `/oauth2/token`

Exchange Authorization Code or JWT assertion for Access Token

**Authorization Code Flow:**

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  // Required for Confidential

grant_type=authorization_code // Supports both Confidential and Public
&code=AUTHORIZATION_CODE
&redirect_uri=REDIRECT_URI
&code_verifier=CODE_VERIFIER  // Required for Public
```

**JWT Bearer Flow:**

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  // Required for Confidential

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer  // Supports Confidential only
&assertion=JWT_ASSERTION
```

**Response:**

```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api::form.form.find api::form.form.create"
}
```

### Token Management Endpoints

#### **POST** `/oauth2/introspect`

Check status and information of Access Token

**Request:**

```http
POST /oauth2/introspect
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN
```

**Response:**

```json
{
  "active": true,
  "client_id": "abc123",
  "scope": "api::form.form.find",
  "exp": 1234567890,
  "iat": 1234564290
}
```

#### **POST** `/oauth2/revoke`

Revoke Access Token

**Request:**

```http
POST /oauth2/revoke
Content-Type: application/json

{
  "jti": "token-jti-here"
}
```

**Response:**

```json
{
  "revoked": true
}
```

### Admin API Endpoints (Used in Admin Panel)

#### OAuth Clients

- `GET /oauth2/clients` - Get clients list
- `POST /oauth2/clients` - Create new client
- `PUT /oauth2/clients/:documentId` - Update client
- `DELETE /oauth2/clients/:documentId` - Delete client
- `PUT /oauth2/clients-rotate/:documentId` - Rotate client secret
- `PUT /oauth2/clients-keypair/:documentId` - Regenerate RSA keypair

#### Access Tokens

- `GET /oauth2/access-tokens` - Get access tokens list
- `POST /oauth2/access-tokens/revoke` - Revoke token

#### Global Settings

- `GET /oauth2/global-settings` - Get global settings
- `PUT /oauth2/global-settings/:documentId` - Update global settings

#### Scopes

- `GET /oauth2/scopes` - Get available scopes list from users-permissions

## 💡 Usage Examples

### 1. Authorization Code Flow with PKCE (Public Client)

#### Step 1: Generate PKCE values

```javascript
// Generate code_verifier (random string 43-128 characters)
const codeVerifier = generateRandomString(128);

// Generate code_challenge (SHA256 hash of verifier)
const codeChallenge = base64UrlEncode(sha256(codeVerifier));
```

#### Step 2: Request Authorization

```javascript
const authUrl = new URL('https://your-strapi.com/oauth2/authorize');
authUrl.searchParams.append('client_id', 'your-client-id');
authUrl.searchParams.append('redirect_uri', 'https://your-app.com/callback');
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('scope', 'api::form.form.find api::form.form.create');
authUrl.searchParams.append('state', 'random-state-value');
authUrl.searchParams.append('code_challenge', codeChallenge);
authUrl.searchParams.append('code_challenge_method', 'S256');

// Redirect user to authUrl
window.location.href = authUrl.toString();
```

#### Step 3: Exchange Code for Token

```javascript
// After redirect back to your app with code
const code = new URLSearchParams(window.location.search).get('code');

const response = await fetch('https://your-strapi.com/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://your-app.com/callback',
    code_verifier: codeVerifier,
    client_id: 'your-client-id',
  }),
});

const { access_token } = await response.json();
```

### 2. JWT Bearer Flow (Service-to-Service)

#### Step 1: Create JWT Assertion

```javascript
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Load private key
const privateKey = fs.readFileSync('path/to/private.key', 'utf8');

// Create JWT assertion
const assertion = jwt.sign(
  {
    scope: 'api::form.form.find api::form.form.create',
  },
  privateKey,
  {
    algorithm: 'RS256',
    issuer: 'your-user-id',
    subject: 'your-client-id',
    audience: 'your-strapi.com',
    expiresIn: '5m',
    header: {
      alg: 'RS256',
      typ: 'JWT',
    },
  }
);
```

#### Step 2: Request Access Token

```javascript
const client_id = 'xxxx';
const client_secret = 'xxxx';
const base64 = Buffer.from(`${client_id}:${client_secret}`, 'utf8').toString('base64');
const response = await fetch('https://your-strapi.com/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${base64}`,
  },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: assertion,
  }),
});

const { access_token } = await response.json();
```

### 3. Using Access Token

```javascript
// Call Strapi API with access token
const response = await fetch('https://your-strapi.com/api/forms', {
  headers: {
    Authorization: `Bearer ${access_token}`,
  },
});

const forms = await response.json();
```

## 🔐 Security Best Practices

### For Confidential Clients

1. **Store `client_secret` securely** - Don't hardcode in code
2. **Use HTTPS only** - Never send credentials over HTTP
3. **Rotate secrets periodically** - Change client secret regularly
4. **Validate redirect URIs** - Use only registered URIs

### For Public Clients

1. **Always use PKCE** - Mandatory by plugin
2. **Use `S256` code challenge method** - More secure than `plain`
3. **Validate state parameter** - Prevent CSRF attacks
4. **Store `code_verifier` in memory** - Don't store in localStorage

### For JWT Bearer Flow

1. **Protect Private Key** - Prevent leakage
2. **Set short assertion expiration** - 5 minutes or less
3. **Use strong RSA keys** - At least 2048-bit
4. **Rotate key pairs periodically** - For security

### General

1. **Validate scopes strictly** - Grant only necessary permissions
2. **Monitor access tokens** - Check for unusual activity
3. **Revoke tokens when needed** - e.g., when user logs out or changes password
4. **Log security events** - Record login, token issuance, revocation

## 🎨 Screenshots

_(Add Admin UI screenshots if desired)_

- Global Settings Page
- OAuth Clients List
- Create Client Modal
- Client Credentials Display
- Access Tokens List

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT

## 📞 Support

For more information or to report issues, please contact: siangsanan.sorasak@gmail.com

---

Developed by Sorasak Siangsanan, CTO of Isaraseri
