# API Endpoint Refactoring Analysis

## Executive Summary
Based on the HAR file analysis and codebase review, several REST API endpoints are defined but never used. This document identifies unnecessary endpoints that can be safely removed to simplify the codebase.

## HAR File Analysis - Actually Used Endpoints

### Port 9000 (Auth Server) - Called from HAR:
1. `GET /.well-known/oauth-authorization-server` ✅ **USED** (OAuth2 discovery)
2. `POST /oauth2/register` ✅ **USED** (Client registration)
3. `GET /oauth2/authorize` ✅ **USED** (Authorization flow)
4. `POST /oauth2/consent` ✅ **USED** (User consent)

### Port 8080 (Resource Server) - Called from HAR:
1. `GET /.well-known/oauth-protected-resource` ✅ **USED** (Resource server discovery)

## Template Usage Analysis

### Endpoints Called from Templates:
- `GET /` ✅ **USED** (Home redirect from error pages)
- `GET /api/config` ✅ **USED** (login.html JavaScript)
- `POST /api/auth/session` ✅ **USED** (login.html JavaScript)
- `GET /oauth2/authorize` ✅ **USED** (login.html redirect)
- `POST /oauth2/consent` ✅ **USED** (consent.html form)
- `POST /oauth2/logout` ✅ **USED** (consent.html form)

## Defined But Unused Endpoints - CANDIDATES FOR REMOVAL

### FirebaseAuthController.java - Unused Endpoints:

#### 1. `/login` - GET ❌ **UNUSED** 
```java
@GetMapping("/login")
public String login() {
    return "login";
}
```
**Reason**: Login page is served via `/` endpoint

#### 2. `/login/oauth` (HTML version) - GET ❌ **UNUSED**
```java
@GetMapping(value = "/login/oauth", produces = MediaType.TEXT_HTML_VALUE)
public String loginOAuthHtml() {
    return "login";
}
```
**Reason**: Duplicate of `/` endpoint functionality

#### 3. `/login/oauth` (JSON version) - GET ❌ **UNUSED**
```java
@GetMapping(value = "/login/oauth", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> loginOAuthJson() { ... }
```
**Reason**: Not called from templates or HAR

#### 4. `/login/oauth` - POST ❌ **UNUSED**
```java
@PostMapping("/login/oauth")
public ResponseEntity<Map<String, Object>> loginOAuth(@RequestBody Map<String, String> request) { ... }
```
**Reason**: Not called from templates or HAR

#### 5. `/login/oauth/authorize` - GET ❌ **UNUSED**
```java
@GetMapping("/login/oauth/authorize")
public String loginOAuthAuthorize() { ... }
```
**Reason**: Not called from templates or HAR

#### 6. `/api/auth/firebase` - POST ❌ **UNUSED**
```java
@PostMapping("/api/auth/firebase")
public ResponseEntity<Map<String, Object>> authenticateFirebase(@RequestBody FirebaseAuthRequest request) { ... }
```
**Reason**: Not called from templates or HAR

#### 7. `/login/oauth/access_token` - POST ❌ **UNUSED**
```java
@PostMapping("/login/oauth/access_token")
public ResponseEntity<Map<String, Object>> loginOAuthAccessToken(@RequestBody Map<String, String> request) { ... }
```
**Reason**: Not called from templates or HAR

#### 8. `/logout` - POST ❌ **UNUSED**
```java
@PostMapping("/logout")
public String logout() { ... }
```
**Reason**: Different from `/oauth2/logout` which is actually used

#### 9. `/error` - GET ❌ **UNUSED**
```java
@GetMapping("/error")
public String error() {
    return "error/general_error";
}
```
**Reason**: Spring Boot handles errors automatically

### OAuth2MetadataController.java - Unused Endpoints:

#### 1. `/.well-known/openid-configuration` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> wellKnownConfiguration() { ... }
```
**Reason**: Not called from HAR, OAuth2 discovery uses different endpoint

#### 2. `/oauth2/jwks` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/oauth2/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> jwks() { ... }
```
**Reason**: Not called from HAR or templates

#### 3. `/.well-known/jwks.json` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> publicJwks() { ... }
```
**Reason**: Not called from HAR or templates

#### 4. `/oauth2/health` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/oauth2/health", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> health() { ... }
```
**Reason**: Not called from HAR or templates

#### 5. `/api/health` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/api/health", produces = MediaType.TEXT_PLAIN_VALUE)
public ResponseEntity<String> apiHealth() { ... }
```
**Reason**: Not called from HAR or templates

#### 6. `/config/urls` - GET ❌ **UNUSED**
```java
@GetMapping(value = "/config/urls", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Map<String, Object>> urlsConfig() { ... }
```
**Reason**: Not called from HAR or templates (was likely for removed mcpResourceBaseUrl/testClientRedirectUrl)

### OAuthController.java - Unused Endpoints:

#### 1. `/oauth2/userinfo` - GET ❌ **UNUSED**
```java
@GetMapping("/oauth2/userinfo")
public ResponseEntity<Map<String, Object>> userInfo(HttpServletRequest request) { ... }
```
**Reason**: Not called from HAR or templates

#### ~~2. `/oauth2/refresh` - POST~~ ✅ **KEEP - VALID OAUTH2 ENDPOINT**
```java
@PostMapping("/oauth2/refresh")
public ResponseEntity<?> refreshToken(@RequestParam String grant_type, @RequestParam String refresh_token, ...) { ... }
```
**Reason**: Standard OAuth2 refresh token endpoint - required for token refresh flows

## Critical Endpoints - KEEP THESE

### FirebaseAuthController.java - Essential:
- `GET /` - ✅ **KEEP** (Home page/login)
- `POST /api/auth/session` - ✅ **KEEP** (Used by login.html)
- `GET /api/config` - ✅ **KEEP** (Used by login.html)

### OAuth2MetadataController.java - Essential:
- `GET /.well-known/oauth-authorization-server` - ✅ **KEEP** (OAuth2 discovery)

### OAuthController.java - Essential:
- `GET /oauth2/authorize` - ✅ **KEEP** (Authorization flow)
- `POST /oauth2/consent` - ✅ **KEEP** (User consent)
- `POST /oauth2/token` - ✅ **KEEP** (Token exchange)
- `POST /oauth2/register` - ✅ **KEEP** (Client registration)
- `POST /oauth2/refresh` - ✅ **KEEP** (Token refresh - standard OAuth2)
- `POST /oauth2/logout` - ✅ **KEEP** (Used by consent.html)

## Refactoring Recommendations

### Phase 1: Remove Unused Endpoints (Safe)
1. Remove 9 endpoints from `FirebaseAuthController.java`
2. Remove 6 endpoints from `OAuth2MetadataController.java`  
3. Remove 1 endpoint from `OAuthController.java` (only `/oauth2/userinfo`)

### Phase 2: Consolidate Remaining Logic
1. Move essential endpoints to appropriate controllers
2. Simplify authentication flows
3. Remove unused dependencies and imports

### Estimated Impact
- **Lines of Code Reduced**: ~350-450 lines
- **Complexity Reduction**: 16 unused endpoints removed (keeping oauth2/refresh)
- **Maintenance Burden**: Significantly reduced
- **Risk Level**: Low (unused endpoints)

## Testing Strategy
1. Run existing integration tests
2. Test OAuth2 flow end-to-end
3. Verify template functionality
4. Check HAR file scenarios still work

This refactoring will significantly simplify the codebase while maintaining all actually used functionality.