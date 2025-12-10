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

- **JWT Format**: Access tokens are JSON Web Tokens (JWT).
- **Expiration**: Token expiration time can be configured. (default: 1 hour)
- **Revocation**: Tokens can be revoked immediately.
- **Introspection**: Token status and details can be verified.
- **Tracking**: Token usage is logged (created at, used at, expires at, revoked at).

#### **Token Information**

- JTI (JWT ID): Unique identifier
- Client Information
- User Information (optional)
- Scopes
- Grant Type
- Expiration and Revocation status

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
module.exports = ({ env }) => ({
  'strapi-plugin-oauth2': {
    enabled: true,
    config: {
      jwtAlg: env('OAUTH_JWT_ALG', 'HS256'),
      jwtSignKey: env('OAUTH_JWT_SIGN_KEY'),
      jwtRS256Bits: env.int('OAUTH_RS256_BITS', 2048),
      jwtPublicKey: env('OAUTH_JWT_PUBLIC_KEY', './assets/oauth2/public.key'),
      jwtPrivateKey: env('OAUTH_JWT_PRIVATE_KEY', './assets/oauth2/private.key'),
      accessTokenTTL: env.int('OAUTH_ACCESS_TOKEN_TTL', 3600),
      audience: env('OAUTH_AUD', 'strapi-api'),
      authCodeTtlSeconds: env.int('OAUTH_AUTH_CODE_TTL_SECONDS', 300),
      callbackUrl: env('OAUTH_CALLBACK_URL', ''),
      maxAssertionTtl: env.int('OAUTH_MAX_ASSERTION_TTL', 300),
    },
  },
});
```

### Environment Variables

```env
# OAuth2 Plugin
OAUTH_JWT_ALG=RS256                                         # HS256 or RS256
OAUTH_JWT_SIGN_KEY=xxxxxxx                                  # only HS256: eg. 32+ byte secret;
OAUTH_JWT_PUBLIC_KEY=                                       # only RS256: path of PEM public key file, default: ./assets/strapi-plugin-oauth2/public.key
OAUTH_JWT_PRIVATE_KEY=                                      # only RS256: path of PEM private key file, default: ./assets/strapi-plugin-oauth2/private.key
OAUTH_ACCESS_TOKEN_TTL=3600
OAUTH_AUD=localhost:1337
OAUTH_AUTH_CODE_TTL_SECONDS=300                             # Authorization code expiration time (seconds)
OAUTH_CALLBACK_URL=http://localhost:3000/oauth2/callback    # Callback URL
OAUTH_MAX_ASSERTION_TTL=300                                 # Maximum JWT assertion lifetime (seconds)
OAUTH_RS256_BITS=2048
```

### Middlewares

```javascript
module.exports = [
  'strapi::logger',
  'strapi::errors',
  'plugin::strapi-plugin-oauth2.oauth-verify-token', // before strapi::security
  'strapi::security',
  'strapi::cors',
  'strapi::poweredBy',
  'strapi::query',
  'strapi::body',
  'strapi::session',
  'strapi::favicon',
  'strapi::public',
];
```

## 📚 API Endpoints

### Authorization Endpoints

#### **GET** `/strapi-plugin-oauth2/authorize`

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

#### **POST** `/strapi-plugin-oauth2/token`

Exchange Authorization Code or JWT assertion for Access Token

**Authorization Code Flow:**

```
POST /strapi-plugin-oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  // Required for Confidential

grant_type=authorization_code // Supports both Confidential and Public
&code=AUTHORIZATION_CODE
&redirect_uri=REDIRECT_URI
&code_verifier=CODE_VERIFIER  // Required for Public
```

**JWT Bearer Flow:**

```
POST /strapi-plugin-oauth2/token
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

#### **POST** `/strapi-plugin-oauth2/introspect`

Check status and information of Access Token

**Request:**

```
POST /strapi-plugin-oauth2/introspect
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

#### **POST** `/strapi-plugin-oauth2/revoke`

Revoke Access Token

**Request:**

```http
POST /strapi-plugin-oauth2/revoke
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

- `GET /strapi-plugin-oauth2/clients` - Get clients list
- `POST /strapi-plugin-oauth2/clients` - Create new client
- `PUT /strapi-plugin-oauth2/clients/:documentId` - Update client
- `DELETE /strapi-plugin-oauth2/clients/:documentId` - Delete client
- `PUT /strapi-plugin-oauth2/clients-rotate/:documentId` - Rotate client secret
- `PUT /strapi-plugin-oauth2/clients-keypair/:documentId` - Regenerate RSA keypair

#### Access Tokens

- `GET /strapi-plugin-oauth2/access-tokens` - Get access tokens list
- `POST /strapi-plugin-oauth2/access-tokens/revoke` - Revoke token

#### Global Settings

- `GET /strapi-plugin-oauth2/global-settings` - Get global settings
- `PUT /strapi-plugin-oauth2/global-settings/:documentId` - Update global settings

#### Scopes

- `GET /strapi-plugin-oauth2/scopes` - Get available scopes list from users-permissions

## 🎨 Building Custom Authorization UI

Since this plugin does not provide a built-in authorization UI, you need to implement your own authorization page. Here's a complete guide on how to build it.

### Overview

The authorization UI is responsible for:

1. Receiving OAuth2 authorization request parameters
2. Fetching client and scope information
3. Displaying scope consent UI to the user
4. Submitting user's approval/denial decision
5. Redirecting back to the client application

### Step 1: Create Authorization Page

Create a page that accepts the following query parameters:

| Parameter               | Required            | Description                        |
| ----------------------- | ------------------- | ---------------------------------- |
| `response_type`         | Yes                 | Must be `code`                     |
| `client_id`             | Yes                 | OAuth Client ID                    |
| `redirect_uri`          | Yes                 | Registered redirect URI            |
| `scope`                 | Optional            | Requested scopes (space-separated) |
| `state`                 | Optional            | CSRF protection token              |
| `code_challenge`        | Public clients only | PKCE code challenge                |
| `code_challenge_method` | Public clients only | `plain` or `S256`                  |

**Example URL:**

```
https://your-app.com/strapi-plugin-oauth2/authorize?
  response_type=code&
  client_id=abc123def456&
  redirect_uri=https://client-app.com/callback&
  scope=api::form.form.find%20api::form.form.create&
  state=random-state&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### Step 2: Fetch Client and Scope Information

Call the plugin API to get client details and available scopes:

```javascript
// Encode scopes as comma-separated with URL encoding
const scopeParam = encodeURIComponent(scope.replace(/\s+/g, ','));

const response = await fetch(
  `/strapi-plugin-oauth2/oauth-clients-authorization/${client_id}?scope=${scopeParam}`,
  {
    headers: {
      Authorization: `Bearer ${userAccessToken}`, // User must be authenticated
    },
  }
);

const clientData = await response.json();
```

**Response structure:**

```typescript
{
  documentId: string;
  clientId: string;
  name: string;              // Client name to display
  clientType: 'CONFIDENTIAL' | 'PUBLIC';
  scopes: string[];          // All available scopes for this client
  grantedScopes: string[];   // Scopes already granted by this user
  redirectUris: string[];    // Registered redirect URIs
  // ... other client fields
}
```

### Step 3: Build Scope Consent UI

Display the scopes in a user-friendly format with checkboxes:

```vue
<template>
  <div class="authorization-page">
    <h2>{{ client.name }} wants access to your account</h2>

    <p>Select what {{ client.name }} can access:</p>

    <!-- Approve All Toggle -->
    <div class="approve-all">
      <label>
        <input
          type="checkbox"
          v-model="approveAll"
          @change="toggleApproveAll"
          :disabled="isAllGranted"
        />
        Approve all
      </label>
    </div>

    <!-- Individual Scope Selection -->
    <div v-for="scope in client.scopes" :key="scope" class="scope-item">
      <div class="scope-info">
        <span class="scope-action">{{ getScopeAction(scope) }}</span>
        <span class="scope-name">{{ scope }}</span>
      </div>
      <input
        type="checkbox"
        v-model="scopeSelections[scope].selected"
        :disabled="scopeSelections[scope].granted"
      />
    </div>

    <!-- Action Buttons -->
    <button @click="approve" :disabled="!hasSelectedScopes">Approve</button>
    <button @click="deny">Deny</button>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';

// Get query parameters
const route = useRoute();
const {
  response_type,
  client_id,
  redirect_uri,
  scope,
  state,
  code_challenge,
  code_challenge_method,
} = route.query;

// State
const client = ref(null);
const scopeSelections = ref({});
const approveAll = ref(false);
const isAllGranted = ref(true);

// Fetch client data
onMounted(async () => {
  const scopeParam = encodeURIComponent((scope || '').replace(/\s+/g, ','));
  const response = await fetch(
    `/strapi-plugin-oauth2/oauth-clients-authorization/${client_id}?scope=${scopeParam}`
  );
  client.value = await response.json();

  // Initialize scope selections
  for (const s of client.value.scopes) {
    const granted = client.value.grantedScopes.includes(s);
    scopeSelections.value[s] = {
      selected: granted,
      granted: granted,
    };
    if (!granted) isAllGranted.value = false;
  }
  approveAll.value = isAllGranted.value;
});

// Helper functions
function getScopeAction(scope) {
  const parts = scope.split('.');
  return parts[parts.length - 1]; // e.g., "find", "create", "update"
}

function toggleApproveAll() {
  for (const scope in scopeSelections.value) {
    if (!scopeSelections.value[scope].granted) {
      scopeSelections.value[scope].selected = approveAll.value;
    }
  }
}

const hasSelectedScopes = computed(() => {
  return Object.values(scopeSelections.value).some((s) => s.selected);
});

// Continue to Step 4...
</script>
```

### Step 4: Submit Authorization Decision

When the user clicks "Approve" or "Deny", send the decision to the plugin:

```javascript
async function approve() {
  // Collect selected scopes
  const selectedScopes = Object.keys(scopeSelections.value).filter(
    (scope) => scopeSelections.value[scope].selected
  );

  if (selectedScopes.length === 0) {
    alert('Please select at least one scope to approve.');
    return;
  }

  try {
    const response = await fetch('/strapi-plugin-oauth2/oauth-authorization-codes/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: JSON.stringify({
        approve: true,
        clientId: client_id,
        redirectUri: redirect_uri,
        state: state,
        scopes: selectedScopes,
        codeChallenge: code_challenge, // Optional, for PKCE
        codeChallengeMethod: code_challenge_method, // Optional, for PKCE
      }),
    });

    const { redirectUri } = await response.json();

    // Redirect to client application with authorization code
    window.location.href = redirectUri;
  } catch (error) {
    console.error('Authorization failed:', error);
  }
}

async function deny() {
  // Same as approve but with approve: false
  const selectedScopes = Object.keys(scopeSelections.value).filter(
    (scope) => scopeSelections.value[scope].selected
  );

  try {
    const response = await fetch('/strapi-plugin-oauth2/oauth-authorization-codes/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: JSON.stringify({
        approve: false,
        clientId: client_id,
        redirectUri: redirect_uri,
        state: state,
        scopes: selectedScopes,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method,
      }),
    });

    const { redirectUri } = await response.json();
    window.location.href = redirectUri;
  } catch (error) {
    console.error('Authorization failed:', error);
  }
}
```

### Step 5: Handle Response

After submitting the authorization decision, the plugin will:

1. **Validate** the `redirect_uri` against the client's registered URIs
2. **Generate** an authorization code (if approved)
3. **Return** a redirect URI with the code and state

**Success Response (Approved):**

```json
{
  "redirectUri": "https://client-app.com/callback?code=abc123xyz789&state=random-state"
}
```

**Error Response (Denied or Invalid):**

```json
{
  "redirectUri": "https://client-app.com/callback?error=access_denied&state=random-state"
}
```

Your authorization page should redirect the user to this `redirectUri`.

### Complete Example with PKCE Support

Here's a complete Vue 3 example with PKCE support:

```vue
<template>
  <div class="min-h-screen flex items-center justify-center">
    <div class="card max-w-2xl w-full">
      <h2 class="text-2xl font-bold mb-4">{{ client?.name }} wants access to your Account</h2>

      <p class="mb-6">
        Select what <strong>{{ client?.name }}</strong> can access
      </p>

      <div class="space-y-4">
        <!-- Approve All -->
        <div class="flex justify-end items-center gap-2">
          <span>Approve all</span>
          <input
            type="checkbox"
            v-model="approveAll"
            @change="toggleApproveAll"
            :disabled="isAllGranted"
          />
        </div>

        <!-- Scope List -->
        <div
          v-for="s in client?.scopes || []"
          :key="s"
          class="flex items-center justify-between p-3 border rounded"
        >
          <div class="flex-1">
            <div class="flex gap-2 items-center mb-1">
              <span class="badge" :class="getScopeColorClass(s)">
                {{ getScopeAction(s) }}
              </span>
            </div>
            <p class="text-sm text-gray-600">{{ s }}</p>
          </div>
          <input
            type="checkbox"
            v-model="scopeSelections[s].selected"
            :disabled="scopeSelections[s].granted"
          />
        </div>
      </div>

      <!-- Error Message -->
      <p v-if="error" class="text-red-600 mt-4">{{ error }}</p>

      <!-- Actions -->
      <div class="flex gap-3 mt-6">
        <button
          @click="approveConsent"
          :disabled="!ready || loading"
          class="btn btn-success flex-1"
        >
          {{ loading ? 'Processing...' : 'Approve' }}
        </button>
        <button @click="denyConsent" :disabled="loading" class="btn btn-error">Deny</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';

// Authentication required
definePageMeta({
  requiresAuth: true,
});

const route = useRoute();
const { response_type, client_id, redirect_uri, scope, state } = route.query;

// Validate required parameters
if (!response_type || !client_id || !redirect_uri) {
  throw createError({
    statusCode: 400,
    statusMessage: 'Missing required OAuth2 parameters',
  });
}

if (response_type !== 'code') {
  throw createError({
    statusCode: 400,
    statusMessage: 'Unsupported response type',
  });
}

// State
const loading = ref(false);
const client = ref(null);
const scopeSelections = ref({});
const approveAll = ref(false);
const error = ref('');
const isAllGranted = ref(true);
const codeChallenge = ref('');
const codeVerifier = ref('');
const codeChallengeMethod = ref('S256');

// PKCE utilities
const generateCodeVerifier = () => {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
};

const base64UrlEncode = (buffer) => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

const generateCodeChallenge = async (verifier) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(hash);
};

const ready = computed(() => {
  return codeChallenge.value && codeChallengeMethod.value && codeVerifier.value;
});

const hasSelectedScopes = computed(() => {
  return Object.values(scopeSelections.value).some((s) => s.selected);
});

// Initialize
onMounted(async () => {
  // Generate PKCE values
  codeVerifier.value = generateCodeVerifier();
  localStorage.setItem('oauth2_code_verifier', codeVerifier.value);

  if (codeChallengeMethod.value === 'plain') {
    codeChallenge.value = codeVerifier.value;
  } else {
    codeChallenge.value = await generateCodeChallenge(codeVerifier.value);
  }

  // Fetch client data
  try {
    const scopeParam = encodeURIComponent((scope || '').replace(/\s+/g, ','));
    const response = await fetch(
      `/strapi-plugin-oauth2/oauth-clients-authorization/${client_id}?scope=${scopeParam}`,
      {
        headers: {
          Authorization: `Bearer ${getUserToken()}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error('Failed to fetch client data');
    }

    client.value = await response.json();

    // Initialize scope selections
    for (const s of client.value.scopes) {
      const granted = client.value.grantedScopes.includes(s);
      scopeSelections.value[s] = {
        selected: granted,
        granted: granted,
      };
      if (!granted) isAllGranted.value = false;
    }
    approveAll.value = isAllGranted.value;
  } catch (err) {
    error.value = err.message;
  }
});

// Helper functions
function getScopeAction(scope) {
  const parts = scope.split('.');
  return parts[parts.length - 1];
}

function getScopeColorClass(scope) {
  const action = getScopeAction(scope);
  if (action.includes('find') || action.includes('get')) return 'badge-success';
  if (action.includes('create')) return 'badge-info';
  if (action.includes('update')) return 'badge-warning';
  if (action.includes('delete')) return 'badge-error';
  return '';
}

function toggleApproveAll() {
  for (const scope in scopeSelections.value) {
    if (!scopeSelections.value[scope].granted) {
      scopeSelections.value[scope].selected = approveAll.value;
    }
  }
}

async function approveConsent() {
  if (!hasSelectedScopes.value) {
    error.value = 'Please select at least one scope to approve.';
    return;
  }

  error.value = '';
  loading.value = true;

  try {
    const selectedScopes = Object.keys(scopeSelections.value).filter(
      (scope) => scopeSelections.value[scope].selected
    );

    const response = await fetch('/strapi-plugin-oauth2/oauth-authorization-codes/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${getUserToken()}`,
      },
      body: JSON.stringify({
        approve: true,
        clientId: client_id,
        redirectUri: redirect_uri,
        state: state,
        scopes: selectedScopes,
        codeChallenge: codeChallenge.value,
        codeChallengeMethod: codeChallengeMethod.value,
      }),
    });

    if (!response.ok) {
      throw new Error('Authorization failed');
    }

    const { redirectUri: finalRedirectUri } = await response.json();
    window.location.href = finalRedirectUri;
  } catch (err) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function denyConsent() {
  loading.value = true;

  try {
    const selectedScopes = Object.keys(scopeSelections.value).filter(
      (scope) => scopeSelections.value[scope].selected
    );

    const response = await fetch('/strapi-plugin-oauth2/oauth-authorization-codes/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${getUserToken()}`,
      },
      body: JSON.stringify({
        approve: false,
        clientId: client_id,
        redirectUri: redirect_uri,
        state: state,
        scopes: selectedScopes,
        codeChallenge: codeChallenge.value,
        codeChallengeMethod: codeChallengeMethod.value,
      }),
    });

    const { redirectUri: finalRedirectUri } = await response.json();
    window.location.href = finalRedirectUri;
  } catch (err) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function getUserToken() {
  // Implement based on your auth system
  return localStorage.getItem('jwt') || sessionStorage.getItem('jwt');
}
</script>

<style scoped>
.badge {
  @apply px-2 py-1 rounded text-xs font-semibold;
}
.badge-success {
  @apply bg-green-100 text-green-800;
}
.badge-info {
  @apply bg-blue-100 text-blue-800;
}
.badge-warning {
  @apply bg-yellow-100 text-yellow-800;
}
.badge-error {
  @apply bg-red-100 text-red-800;
}

.btn {
  @apply px-4 py-2 rounded font-semibold transition;
}
.btn-success {
  @apply bg-green-600 text-white hover:bg-green-700;
}
.btn-error {
  @apply bg-red-600 text-white hover:bg-red-700;
}
.btn:disabled {
  @apply opacity-50 cursor-not-allowed;
}
</style>
```

### Important Notes

1. **Authentication Required**: The user must be authenticated before accessing the authorization page. Check their session/token before displaying the UI.

2. **PKCE for Public Clients**: If the client is a Public client, PKCE (`code_challenge` and `code_challenge_method`) is mandatory.

3. **Scope Encoding**: When passing scopes to the API, convert spaces to commas and URL-encode: `scope.replace(/\s+/g, ',')` then `encodeURIComponent()`.

4. **Store Code Verifier**: Save `code_verifier` in localStorage or sessionStorage so it can be used later when exchanging the authorization code for an access token.

5. **Redirect URI Validation**: The plugin validates that the `redirect_uri` matches one of the registered URIs for the client. If validation fails, an error will be returned.

6. **State Parameter**: Always validate the `state` parameter when redirected back to prevent CSRF attacks.

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
const authUrl = new URL('https://your-strapi.com/strapi-plugin-oauth2/authorize');
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

const response = await fetch('https://your-strapi.com/strapi-plugin-oauth2/token', {
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
const response = await fetch('https://your-strapi.com/strapi-plugin-oauth2/token', {
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
