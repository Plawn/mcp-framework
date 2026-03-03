#!/usr/bin/env bun
/**
 * MCP OAuth diagnostic script
 * Tests the full OAuth flow as Claude Desktop would perform it,
 * following the MCP draft spec (2025-11-25).
 */

const BASE_URL = process.argv[2] || "https://blumana-mcp.temp3-webservice.blumana.app";
const MCP_ENDPOINT = `${BASE_URL}/mcp`;

const OK = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const WARN = "\x1b[33m⚠\x1b[0m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

let stepNum = 0;
function step(title: string) {
  stepNum++;
  console.log(`\n${BOLD}━━━ Step ${stepNum}: ${title} ━━━${RESET}`);
}

function check(ok: boolean, msg: string) {
  console.log(`  ${ok ? OK : FAIL} ${msg}`);
  return ok;
}

function warn(msg: string) {
  console.log(`  ${WARN} ${msg}`);
}

async function fetchSafe(url: string, init?: RequestInit): Promise<Response | null> {
  try {
    return await fetch(url, { ...init, redirect: "manual" });
  } catch (e: any) {
    console.log(`  ${FAIL} Fetch failed: ${e.message}`);
    return null;
  }
}

// ─────────────────────────────────────────────
// Step 1: Initial unauthenticated MCP request
// ─────────────────────────────────────────────
step("Initial MCP request (expect 401)");

const mcp401 = await fetchSafe(MCP_ENDPOINT, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
});

if (!mcp401) {
  console.log(`${FAIL} Cannot reach ${MCP_ENDPOINT} - aborting`);
  process.exit(1);
}

check(mcp401.status === 401, `Status: ${mcp401.status} (expect 401)`);

const wwwAuth = mcp401.headers.get("www-authenticate");
console.log(`  WWW-Authenticate: ${wwwAuth || "(missing)"}`);

let resourceMetadataUrl: string | null = null;
if (wwwAuth) {
  const match = wwwAuth.match(/resource_metadata="([^"]+)"/);
  if (match) {
    resourceMetadataUrl = match[1];
    check(true, `resource_metadata URL: ${resourceMetadataUrl}`);
  } else {
    check(false, "resource_metadata not found in WWW-Authenticate header");
  }

  // Check for scope hint
  const scopeMatch = wwwAuth.match(/scope="([^"]+)"/);
  if (scopeMatch) {
    console.log(`  Scope hint: ${scopeMatch[1]}`);
  } else {
    warn("No scope hint in WWW-Authenticate (optional per spec)");
  }
} else {
  check(false, "Missing WWW-Authenticate header (REQUIRED by MCP spec)");
}

// ─────────────────────────────────────────────
// Step 2: Protected Resource Metadata (RFC 9728)
// ─────────────────────────────────────────────
step("Protected Resource Metadata discovery");

// Try path-specific first (as Claude Desktop would)
const prmUrls = [
  `${BASE_URL}/.well-known/oauth-protected-resource/mcp`,
  `${BASE_URL}/.well-known/oauth-protected-resource`,
];

if (resourceMetadataUrl) {
  // If WWW-Authenticate gave us a URL, try it first
  prmUrls.unshift(resourceMetadataUrl);
}

let prm: any = null;
let prmSource = "";
for (const url of [...new Set(prmUrls)]) {
  const res = await fetchSafe(url);
  if (res && res.ok) {
    try {
      prm = await res.json();
      prmSource = url;
      check(true, `Found at: ${url}`);
      break;
    } catch {
      check(false, `Invalid JSON at: ${url}`);
    }
  } else {
    console.log(`  - ${url}: ${res?.status || "unreachable"}`);
  }
}

if (!prm) {
  console.log(`${FAIL} No protected resource metadata found - aborting`);
  process.exit(1);
}

console.log(`  Response:`);
console.log(JSON.stringify(prm, null, 2).split("\n").map(l => `    ${l}`).join("\n"));

// Validate required fields
check(!!prm.resource, `resource field: ${prm.resource || "(missing)"}`);
check(
  Array.isArray(prm.authorization_servers) && prm.authorization_servers.length > 0,
  `authorization_servers: ${JSON.stringify(prm.authorization_servers)}`
);

// Check resource matches what Claude Desktop would expect
const expectedResource = MCP_ENDPOINT.replace(/\/$/, "");
if (prm.resource !== expectedResource && prm.resource !== BASE_URL) {
  warn(`resource "${prm.resource}" may not match MCP endpoint "${expectedResource}"`);
}

const authServerUrl = prm.authorization_servers?.[0];
if (!authServerUrl) {
  console.log(`${FAIL} No authorization server URL - aborting`);
  process.exit(1);
}

// ─────────────────────────────────────────────
// Step 3: Authorization Server Metadata
// ─────────────────────────────────────────────
step("Authorization Server Metadata discovery");

// Try both OAuth 2.0 AS Metadata and OIDC Discovery
const asMetaUrls = [
  `${authServerUrl}/.well-known/oauth-authorization-server`,
  `${authServerUrl}/.well-known/openid-configuration`,
];

let asMeta: any = null;
let asMetaSource = "";
for (const url of asMetaUrls) {
  const res = await fetchSafe(url);
  if (res && res.ok) {
    try {
      asMeta = await res.json();
      asMetaSource = url;
      check(true, `Found at: ${url}`);
      break;
    } catch {
      check(false, `Invalid JSON at: ${url}`);
    }
  } else {
    console.log(`  - ${url}: ${res?.status || "unreachable"}`);
  }
}

if (!asMeta) {
  console.log(`${FAIL} No authorization server metadata found - aborting`);
  process.exit(1);
}

console.log(`  Response:`);
console.log(JSON.stringify(asMeta, null, 2).split("\n").map(l => `    ${l}`).join("\n"));

// Validate required fields
check(!!asMeta.issuer, `issuer: ${asMeta.issuer || "(missing)"}`);
check(!!asMeta.authorization_endpoint, `authorization_endpoint: ${asMeta.authorization_endpoint || "(missing)"}`);
check(!!asMeta.token_endpoint, `token_endpoint: ${asMeta.token_endpoint || "(missing)"}`);

// Check issuer matches AS URL
if (asMeta.issuer !== authServerUrl) {
  check(false, `issuer "${asMeta.issuer}" does NOT match AS URL "${authServerUrl}" (RFC 8414 violation)`);
} else {
  check(true, `issuer matches AS URL`);
}

// PKCE support (REQUIRED by MCP spec)
const pkceMethods = asMeta.code_challenge_methods_supported;
if (!pkceMethods) {
  check(false, "code_challenge_methods_supported MISSING (MCP clients MUST refuse to proceed)");
} else {
  check(pkceMethods.includes("S256"), `PKCE S256 supported: ${JSON.stringify(pkceMethods)}`);
}

// Registration endpoint
if (asMeta.registration_endpoint) {
  check(true, `registration_endpoint: ${asMeta.registration_endpoint}`);
} else {
  warn("No registration_endpoint (DCR not available)");
}

// CIMD support
if (asMeta.client_id_metadata_document_supported) {
  check(true, "client_id_metadata_document_supported: true");
} else {
  warn("client_id_metadata_document_supported not set (Claude Desktop may skip CIMD)");
}

// Grant types
const grantTypes = asMeta.grant_types_supported || [];
check(grantTypes.includes("authorization_code"), `grant_type authorization_code: ${grantTypes.includes("authorization_code")}`);
check(grantTypes.includes("refresh_token"), `grant_type refresh_token: ${grantTypes.includes("refresh_token")}`);

// ─────────────────────────────────────────────
// Step 4: Dynamic Client Registration (RFC 7591)
// ─────────────────────────────────────────────
step("Dynamic Client Registration");

const regEndpoint = asMeta.registration_endpoint;
if (!regEndpoint) {
  warn("No registration endpoint, skipping DCR test");
} else {
  const dcrBody = {
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };

  console.log(`  POST ${regEndpoint}`);
  console.log(`  Body: ${JSON.stringify(dcrBody, null, 2).split("\n").map(l => `    ${l}`).join("\n")}`);

  const dcrRes = await fetchSafe(regEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(dcrBody),
  });

  if (dcrRes) {
    const dcrStatus = dcrRes.status;
    const dcrJson = await dcrRes.json().catch(() => null);
    check(dcrStatus === 201 || dcrStatus === 200, `Status: ${dcrStatus}`);
    console.log(`  Response:`);
    console.log(JSON.stringify(dcrJson, null, 2).split("\n").map(l => `    ${l}`).join("\n"));

    if (dcrJson) {
      check(!!dcrJson.client_id, `client_id: ${dcrJson.client_id || "(missing)"}`);
      const dcrGrantTypes = dcrJson.grant_types || [];
      check(dcrGrantTypes.includes("refresh_token"), `grant_types includes refresh_token: ${dcrGrantTypes.includes("refresh_token")}`);
    }
  }
}

// ─────────────────────────────────────────────
// Step 5: Authorization endpoint (redirect check)
// ─────────────────────────────────────────────
step("Authorization endpoint redirect");

const authEndpoint = asMeta.authorization_endpoint;
const fakeState = "test-state-" + Date.now();
const fakeChallenge = "test-challenge-abc123";
const resourceParam = prm.resource || MCP_ENDPOINT;

const authParams = new URLSearchParams({
  response_type: "code",
  client_id: "Claude",
  redirect_uri: "https://claude.ai/api/mcp/auth_callback",
  scope: "openid profile email",
  state: fakeState,
  code_challenge: fakeChallenge,
  code_challenge_method: "S256",
  resource: resourceParam,
});

const authUrl = `${authEndpoint}?${authParams}`;
console.log(`  GET ${authEndpoint}?...`);
console.log(`    resource=${resourceParam}`);

const authRes = await fetchSafe(authUrl);
if (authRes) {
  const isRedirect = [301, 302, 303, 307, 308].includes(authRes.status);
  check(isRedirect, `Status: ${authRes.status} (expect 3xx redirect)`);

  const location = authRes.headers.get("location");
  if (location) {
    console.log(`  Redirects to: ${location.substring(0, 120)}...`);

    // Parse the redirect URL to check what params are forwarded
    try {
      const redirectUrl = new URL(location);
      const redirectParams = redirectUrl.searchParams;

      check(!!redirectParams.get("client_id"), `client_id forwarded: ${redirectParams.get("client_id")}`);
      check(!!redirectParams.get("redirect_uri"), `redirect_uri forwarded: ${redirectParams.get("redirect_uri")}`);
      check(!!redirectParams.get("state"), `state forwarded: ${redirectParams.get("state") === fakeState}`);
      check(!!redirectParams.get("code_challenge"), `code_challenge forwarded: ${!!redirectParams.get("code_challenge")}`);
      check(!!redirectParams.get("code_challenge_method"), `code_challenge_method forwarded: ${redirectParams.get("code_challenge_method")}`);

      const resourceForwarded = redirectParams.get("resource");
      if (resourceForwarded) {
        check(true, `resource param forwarded: ${resourceForwarded}`);
      } else {
        check(false, "resource param NOT forwarded to Keycloak (RFC 8707)");
      }

      // Check scope
      const scopeForwarded = redirectParams.get("scope");
      if (scopeForwarded) {
        check(true, `scope forwarded: ${scopeForwarded}`);
      }
    } catch {
      warn("Could not parse redirect URL");
    }
  } else {
    check(false, "No Location header in redirect");
  }
}

// ─────────────────────────────────────────────
// Step 6: CORS headers check
// ─────────────────────────────────────────────
step("CORS preflight checks");

const corsEndpoints = [
  { url: `${BASE_URL}/oauth/token`, method: "POST" },
  { url: MCP_ENDPOINT, method: "POST" },
  { url: `${BASE_URL}/.well-known/oauth-protected-resource`, method: "GET" },
];

for (const { url, method } of corsEndpoints) {
  const corsRes = await fetchSafe(url, {
    method: "OPTIONS",
    headers: {
      "Origin": "https://claude.ai",
      "Access-Control-Request-Method": method,
      "Access-Control-Request-Headers": "content-type,authorization",
    },
  });

  if (corsRes) {
    const acao = corsRes.headers.get("access-control-allow-origin");
    const acam = corsRes.headers.get("access-control-allow-methods");
    const acah = corsRes.headers.get("access-control-allow-headers");
    const ok = !!acao;
    check(ok, `OPTIONS ${url.replace(BASE_URL, "")}: ${corsRes.status} | Allow-Origin: ${acao || "MISSING"}`);
    if (!ok) {
      console.log(`    Allow-Methods: ${acam || "MISSING"}`);
      console.log(`    Allow-Headers: ${acah || "MISSING"}`);
    }
  }
}

// ─────────────────────────────────────────────
// Step 7: Token endpoint format check
// ─────────────────────────────────────────────
step("Token endpoint response format");

const tokenEndpoint = asMeta.token_endpoint;
console.log(`  POST ${tokenEndpoint}`);

// Send a deliberately bad token request to see the error format
const badTokenRes = await fetchSafe(tokenEndpoint, {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://claude.ai",
  },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: "fake-code",
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    client_id: "Claude",
    code_verifier: "fake-verifier",
    resource: resourceParam,
  }).toString(),
});

if (badTokenRes) {
  console.log(`  Status: ${badTokenRes.status} (expect 400 for bad code)`);
  const ct = badTokenRes.headers.get("content-type");
  console.log(`  Content-Type: ${ct}`);

  // Check CORS on response
  const acao = badTokenRes.headers.get("access-control-allow-origin");
  check(!!acao, `CORS Allow-Origin on response: ${acao || "MISSING"}`);

  // Check response body
  const body = await badTokenRes.text();
  console.log(`  Body: ${body.substring(0, 500)}`);

  // Check for standard OAuth error format
  try {
    const errJson = JSON.parse(body);
    if (errJson.error) {
      check(true, `Standard OAuth error format: ${errJson.error}`);
    }
  } catch {
    warn("Response is not JSON");
  }
}

// ─────────────────────────────────────────────
// Step 8: Bearer token on MCP endpoint
// ─────────────────────────────────────────────
step("MCP endpoint with fake Bearer token");

const mcpWithToken = await fetchSafe(MCP_ENDPOINT, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer fake-token-for-testing",
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test-script", version: "1.0" },
    },
    id: 1,
  }),
});

if (mcpWithToken) {
  console.log(`  Status: ${mcpWithToken.status}`);
  const ct = mcpWithToken.headers.get("content-type");
  console.log(`  Content-Type: ${ct}`);

  // Check CORS
  const acao = mcpWithToken.headers.get("access-control-allow-origin");
  check(!!acao, `CORS Allow-Origin: ${acao || "MISSING"}`);

  // Show all headers
  console.log(`  Response headers:`);
  mcpWithToken.headers.forEach((v, k) => {
    console.log(`    ${k}: ${v}`);
  });

  const body = await mcpWithToken.text();
  console.log(`  Body (first 500 chars): ${body.substring(0, 500)}`);
}

// ─────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────
console.log(`\n${BOLD}━━━ Summary ━━━${RESET}`);
console.log(`Server: ${BASE_URL}`);
console.log(`MCP endpoint: ${MCP_ENDPOINT}`);
console.log(`Protected Resource Metadata: ${prmSource}`);
console.log(`  resource: ${prm?.resource}`);
console.log(`  authorization_servers: ${JSON.stringify(prm?.authorization_servers)}`);
console.log(`AS Metadata: ${asMetaSource}`);
console.log(`  issuer: ${asMeta?.issuer}`);
console.log(`  authorization_endpoint: ${asMeta?.authorization_endpoint}`);
console.log(`  token_endpoint: ${asMeta?.token_endpoint}`);
console.log(`  registration_endpoint: ${asMeta?.registration_endpoint}`);
console.log(`  PKCE: ${JSON.stringify(asMeta?.code_challenge_methods_supported)}`);
console.log(`  CIMD: ${asMeta?.client_id_metadata_document_supported || "not set"}`);
