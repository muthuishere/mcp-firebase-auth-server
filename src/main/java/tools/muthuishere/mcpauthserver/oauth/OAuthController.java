package tools.muthuishere.mcpauthserver.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import tools.muthuishere.mcpauthserver.config.ServerUrlsConfig;
import tools.muthuishere.mcpauthserver.firebase.FirebaseAuthService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth2 Controller handling OAuth 2.0 authorization server endpoints
 * Separated from Firebase authentication concerns for better architecture
 */
@Controller
public class OAuthController {

    @Autowired
    private FirebaseAuthService firebaseAuthService;

    @Autowired
    private OAuth2Service oauth2Service;

    @Autowired
    private ServerUrlsConfig serverUrlsConfig;

    // Store authorization codes temporarily (in production, use Redis or database)
    private final Map<String, AuthorizationCodeInfo> authorizationCodes = new ConcurrentHashMap<>();
    
    // Store registered clients temporarily (in production, use database)
    private final Map<String, RegisteredClientInfo> registeredClients = new ConcurrentHashMap<>();

    // Store CSRF protection
    private final Map<String, String> csrfTokens = new ConcurrentHashMap<>();

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * OAuth2 Authorization endpoint - RFC 6749
     * Handles authorization code flow initiation
     */
    @GetMapping("/oauth2/authorize")
    public String authorize(
            @RequestParam String client_id,
            @RequestParam String redirect_uri,
            @RequestParam(required = false) String response_type,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String code_challenge,
            @RequestParam(required = false) String code_challenge_method,
            Model model,
            HttpServletRequest request) {

        // Auto-register client if not found (lenient mode for development)
        RegisteredClientInfo client = registeredClients.get(client_id);
        if (client == null) {
            // Auto-register the client with the provided redirect_uri
            client = new RegisteredClientInfo();
            client.setClientId(client_id);
            client.setClientSecret(generateClientSecret()); // Generate a secret for the client
            client.setClientName("Auto-registered Client: " + client_id);
            client.setRedirectUris(java.util.List.of(redirect_uri)); // Use the provided redirect_uri
            client.setTokenEndpointAuthMethod("none"); // For public clients (VS Code MCP)
            client.setGrantTypes(java.util.List.of("authorization_code"));
            client.setResponseTypes(java.util.List.of("code"));
            client.setScope(scope != null ? scope : "read:email");
            client.setCreatedAt(System.currentTimeMillis());
            
            // Store the auto-registered client
            registeredClients.put(client_id, client);
            
            System.out.println("Auto-registered new client: " + client_id + " with redirect_uri: " + redirect_uri);
        }

        // Validate redirect_uri (allow if client was just auto-registered or if it matches existing)
        if (!client.getRedirectUris().contains(redirect_uri)) {
            // For auto-registered clients or lenient mode, add the redirect_uri if it's valid
            if (isValidRedirectUri(redirect_uri)) {
                // Add the new redirect_uri to existing client
                java.util.List<String> updatedUris = new java.util.ArrayList<>(client.getRedirectUris());
                updatedUris.add(redirect_uri);
                client.setRedirectUris(updatedUris);
                System.out.println("Added new redirect_uri to client " + client_id + ": " + redirect_uri);
            } else {
                return "redirect:/error?error=invalid_request&error_description=" +
                        URLEncoder.encode("Invalid redirect_uri format", StandardCharsets.UTF_8);
            }
        }

        // Validate response_type
        if (!"code".equals(response_type)) {
            return "redirect:" + redirect_uri + "?error=unsupported_response_type&error_description=" +
                    URLEncoder.encode("Only 'code' response_type is supported", StandardCharsets.UTF_8) +
                    (state != null ? "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8) : "");
        }

        // Generate CSRF token
        String csrfToken = generateSecureToken();
        csrfTokens.put(csrfToken, client_id);

        // Store authorization request parameters in session
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setClientId(client_id);
        authRequest.setRedirectUri(redirect_uri);
        authRequest.setResponseType(response_type);
        authRequest.setScope(scope);
        authRequest.setState(state);
        authRequest.setCodeChallenge(code_challenge);
        authRequest.setCodeChallengeMethod(code_challenge_method);

        // Store in session (in production, use secure session storage)
        request.getSession().setAttribute("oauth2_auth_request", authRequest);
        request.getSession().setAttribute("csrf_token", csrfToken);

        // Check if user is authenticated via session
        String authenticatedUserId = (String) request.getSession().getAttribute("authenticated_user_id");
        String authenticatedUserEmail = (String) request.getSession().getAttribute("authenticated_user_email");
        String authenticatedUserName = (String) request.getSession().getAttribute("authenticated_user_name");

        // If user is not authenticated or session data is incomplete, redirect to login
        if (authenticatedUserId == null || authenticatedUserId.trim().isEmpty() || 
            authenticatedUserEmail == null || authenticatedUserEmail.trim().isEmpty()) {
            
            // Store OAuth parameters for after login
            model.addAttribute("client_id", client_id);
            model.addAttribute("redirect_uri", redirect_uri);
            model.addAttribute("scope", scope != null ? scope : "read");
            model.addAttribute("state", state);
            model.addAttribute("projectId", firebaseAuthService.getProjectId());
            model.addAttribute("isOAuthFlow", true);
            
            return "login";
        }

        // User is authenticated - show consent page
        model.addAttribute("client_id", client_id);
        model.addAttribute("client_name", client.getClientName() != null ? client.getClientName() : client_id);
        model.addAttribute("redirect_uri", redirect_uri);
        model.addAttribute("scope", scope != null ? scope : "read");
        model.addAttribute("state", state);
        model.addAttribute("csrf_token", csrfToken);
        model.addAttribute("auth_server_url", serverUrlsConfig.getAuthServerBaseUrl());
        
        // Add authenticated user information to consent page
        model.addAttribute("currentUserEmail", authenticatedUserEmail);
        model.addAttribute("currentUserName", authenticatedUserName != null ? authenticatedUserName : "Unknown User");
        model.addAttribute("currentUserId", authenticatedUserId);

        return "consent";
    }

    /**
     * OAuth2 Consent handling - processes user consent
     */
    @PostMapping("/oauth2/consent")
    public String handleConsent(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String approved,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String csrf_token,
            @RequestParam(required = false) String firebase_token,
            HttpServletRequest request) {

        try {
            // Get authorization request from session
            AuthorizationRequest authRequest = (AuthorizationRequest) request.getSession().getAttribute("oauth2_auth_request");
            if (authRequest == null) {
                return "redirect:/error?error=invalid_request&error_description=" + 
                       URLEncoder.encode("No authorization request found", StandardCharsets.UTF_8);
            }

            // Get CSRF token from session
            String sessionCsrfToken = (String) request.getSession().getAttribute("csrf_token");
            
            // Use parameters from session if not provided in form
            if (client_id == null) client_id = authRequest.getClientId();
            if (redirect_uri == null) redirect_uri = authRequest.getRedirectUri();
            if (scope == null) scope = authRequest.getScope();
            if (state == null) state = authRequest.getState();
            if (csrf_token == null) csrf_token = sessionCsrfToken;

            // Validate CSRF token
            if (csrf_token == null || !csrf_token.equals(sessionCsrfToken) || !csrfTokens.containsKey(csrf_token)) {
                return "redirect:/error?error=invalid_request&error_description=" + 
                       URLEncoder.encode("Invalid CSRF token", StandardCharsets.UTF_8);
            }

            // Remove used CSRF token
            csrfTokens.remove(csrf_token);

            // Check if user denied (approved="false" or action="deny")
            boolean isDenied = "deny".equals(action) || "false".equals(approved);
            
            if (isDenied) {
                // User denied authorization
                String redirectUrl = redirect_uri + "?error=access_denied&error_description=" +
                        URLEncoder.encode("User denied authorization", StandardCharsets.UTF_8);
                if (state != null) {
                    redirectUrl += "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
                }
                return "redirect:" + redirectUrl;
            }

            // Get authenticated user from session (already verified during login)
            String uid = (String) request.getSession().getAttribute("authenticated_user_id");
            if (uid == null || uid.trim().isEmpty()) {
                return "redirect:/error?error=invalid_request&error_description=" + 
                       URLEncoder.encode("User not authenticated", StandardCharsets.UTF_8);
            }
            
            // Get Firebase token from session if not provided
            if (firebase_token == null) {
                firebase_token = (String) request.getSession().getAttribute("firebase_token");
                if (firebase_token != null) {
                    System.out.println("Using Firebase token from session: " + firebase_token.substring(0, Math.min(50, firebase_token.length())) + "...");
                }
            }
            
            // If we still don't have a Firebase token, generate a new one using Firebase service
            if (firebase_token == null) {
                try {
                    // Generate a fresh Firebase custom token for this user
                    firebase_token = firebaseAuthService.createCustomToken(uid);
                    System.out.println("Generated new Firebase custom token for user: " + uid);
                } catch (Exception e) {
                    System.out.println("Failed to generate Firebase token for user " + uid + ": " + e.getMessage());
                    return "redirect:/error?error=server_error&error_description=" + 
                           URLEncoder.encode("Failed to generate Firebase token: " + e.getMessage(), StandardCharsets.UTF_8);
                }
            }

            // Generate authorization code
            String authCode = generateSecureToken();

            // Store authorization code with associated data
            AuthorizationCodeInfo codeInfo = new AuthorizationCodeInfo();
            codeInfo.setCode(authCode);
            codeInfo.setClientId(client_id);
            codeInfo.setRedirectUri(redirect_uri);
            codeInfo.setScope(scope != null ? scope : "read");
            codeInfo.setState(state);
            codeInfo.setUserId(uid);
            codeInfo.setFirebaseToken(firebase_token);
            codeInfo.setCodeChallenge(authRequest.getCodeChallenge());
            codeInfo.setCodeChallengeMethod(authRequest.getCodeChallengeMethod());
            codeInfo.setExpiresAt(System.currentTimeMillis() + 600000); // 10 minutes

            authorizationCodes.put(authCode, codeInfo);

            // Build redirect URL with authorization code and perform redirect
            String redirectUrl = redirect_uri + "?code=" + authCode;
            if (state != null) {
                redirectUrl += "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
            }

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            return "redirect:/error?error=server_error&error_description=" + 
                   URLEncoder.encode("Internal server error: " + e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * OAuth2 Token endpoint - RFC 6749
     * Exchanges authorization code for access token
     */
    @PostMapping("/oauth2/token")
    public ResponseEntity<?> token(
            @RequestParam String grant_type,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String client_secret,
            @RequestParam(required = false) String code_verifier) {

        try {
            if (!"authorization_code".equals(grant_type)) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "unsupported_grant_type");
                errorResponse.put("error_description", "Only authorization_code grant type is supported");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            if (code == null || redirect_uri == null || client_id == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "Missing required parameters");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Retrieve authorization code info
            AuthorizationCodeInfo codeInfo = authorizationCodes.get(code);
            if (codeInfo == null || codeInfo.getExpiresAt() < System.currentTimeMillis()) {
                authorizationCodes.remove(code); // Clean up expired code
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_grant");
                errorResponse.put("error_description", "Invalid or expired authorization code");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validate client_id and redirect_uri
            if (!codeInfo.getClientId().equals(client_id) || !codeInfo.getRedirectUri().equals(redirect_uri)) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_grant");
                errorResponse.put("error_description", "Client ID or redirect URI mismatch");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validate client credentials
            RegisteredClientInfo clientInfo = registeredClients.get(client_id);
            if (clientInfo == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_client");
                errorResponse.put("error_description", "Invalid client credentials");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // For public clients using PKCE, verify code_verifier
            if (codeInfo.getCodeChallenge() != null) {
                if (code_verifier == null) {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_request");
                    errorResponse.put("error_description", "code_verifier required for PKCE");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
                }

                // Verify PKCE code challenge
                if (!oauth2Service.verifyPkceChallenge(code_verifier, codeInfo.getCodeChallenge(), codeInfo.getCodeChallengeMethod())) {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_grant");
                    errorResponse.put("error_description", "Invalid code_verifier");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
                }
            } else {
                // For confidential clients, verify client_secret
                if (!clientInfo.getClientSecret().equals(client_secret)) {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_client");
                    errorResponse.put("error_description", "Invalid client credentials");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
                }
            }

            // Generate JWT access token
            String accessToken = oauth2Service.createJwtAccessToken(codeInfo.getUserId(), client_id, codeInfo.getScope(), codeInfo.getFirebaseToken());
            String refreshToken = oauth2Service.generateRefreshToken(codeInfo.getUserId(), client_id, codeInfo.getScope());

            // Clean up used authorization code
            authorizationCodes.remove(code);

            // Return token response
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("token_type", "Bearer");
            tokenResponse.put("expires_in", oauth2Service.getAccessTokenExpirySeconds());
            tokenResponse.put("refresh_token", refreshToken);
            if (codeInfo.getScope() != null) {
                tokenResponse.put("scope", codeInfo.getScope());
            }

            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Internal server error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * OAuth2 Dynamic Client Registration endpoint - RFC 7591
     */
    @PostMapping("/oauth2/register")
    public ResponseEntity<?> registerClient(@RequestBody Map<String, Object> requestBody) {
        try {
            // Extract client metadata
            String clientName = (String) requestBody.get("client_name");
            @SuppressWarnings("unchecked")
            java.util.List<String> redirectUris = (java.util.List<String>) requestBody.get("redirect_uris");
            String tokenEndpointAuthMethod = (String) requestBody.getOrDefault("token_endpoint_auth_method", "client_secret_basic");
            @SuppressWarnings("unchecked")
            java.util.List<String> grantTypes = (java.util.List<String>) requestBody.getOrDefault("grant_types", java.util.List.of("authorization_code"));
            @SuppressWarnings("unchecked")
            java.util.List<String> responseTypes = (java.util.List<String>) requestBody.getOrDefault("response_types", java.util.List.of("code"));
            String scope = (String) requestBody.getOrDefault("scope", "read");

            // Validate required fields
            if (clientName == null || redirectUris == null || redirectUris.isEmpty()) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_client_metadata");
                errorResponse.put("error_description", "client_name and redirect_uris are required");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validate redirect URIs
            for (String uri : redirectUris) {
                if (!isValidRedirectUri(uri)) {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_redirect_uri");
                    errorResponse.put("error_description", "Invalid redirect URI: " + uri);
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
                }
            }

            // Generate client credentials
            String clientId = generateClientId();
            String clientSecret = generateClientSecret();

            // Create client registration
            RegisteredClientInfo clientInfo = new RegisteredClientInfo();
            clientInfo.setClientId(clientId);
            clientInfo.setClientSecret(clientSecret);
            clientInfo.setClientName(clientName);
            clientInfo.setRedirectUris(redirectUris);
            clientInfo.setTokenEndpointAuthMethod(tokenEndpointAuthMethod);
            clientInfo.setGrantTypes(grantTypes);
            clientInfo.setResponseTypes(responseTypes);
            clientInfo.setScope(scope);
            clientInfo.setCreatedAt(System.currentTimeMillis());

            // Store client registration
            registeredClients.put(clientId, clientInfo);

            // Build response according to RFC 7591
            Map<String, Object> response = new HashMap<>();
            response.put("client_id", clientId);
            response.put("client_secret", clientSecret);
            response.put("client_name", clientName);
            response.put("redirect_uris", redirectUris);
            response.put("token_endpoint_auth_method", tokenEndpointAuthMethod);
            response.put("grant_types", grantTypes);
            response.put("response_types", responseTypes);
            response.put("scope", scope);
            response.put("client_id_issued_at", clientInfo.getCreatedAt() / 1000); // Unix timestamp

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to register client: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * OAuth2 UserInfo endpoint - RFC 6750
     */
    @GetMapping("/oauth2/userinfo")
    public ResponseEntity<?> userInfo(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_token");
                errorResponse.put("error_description", "Missing or invalid Authorization header");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            String accessToken = authHeader.substring(7);

            // Validate and extract user info from JWT token
            Map<String, Object> userInfo = oauth2Service.extractUserInfoFromToken(accessToken);
            if (userInfo == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_token");
                errorResponse.put("error_description", "Invalid or expired access token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to retrieve user info: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * OAuth2 Refresh Token endpoint
     */
    @PostMapping("/oauth2/refresh")
    public ResponseEntity<?> refreshToken(
            @RequestParam String grant_type,
            @RequestParam String refresh_token,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String client_secret,
            @RequestParam(required = false) String scope) {

        try {
            if (!"refresh_token".equals(grant_type)) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "unsupported_grant_type");
                errorResponse.put("error_description", "Only refresh_token grant type is supported");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Refresh the access token
            Map<String, Object> tokenResponse = oauth2Service.refreshAccessToken(refresh_token, client_id, scope);
            
            if (tokenResponse == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_grant");
                errorResponse.put("error_description", "Invalid or expired refresh token");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to refresh token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
//
//    /**
//     * Handle OAuth logout - clears session and redirects back to authorization
//     */
//    @PostMapping("/oauth2/logout")
//    public String oauthLogout(HttpServletRequest request) {
//        // Clear authentication session
//        request.getSession().removeAttribute("authenticated_user_id");
//        request.getSession().removeAttribute("authenticated_user_email");
//        request.getSession().removeAttribute("authenticated_user_name");
//        request.getSession().removeAttribute("firebase_token");
//
//        // Get stored OAuth authorization request to redirect back to authorization
//        AuthorizationRequest authRequest = (AuthorizationRequest) request.getSession().getAttribute("oauth2_auth_request");
//        if (authRequest != null) {
//            String redirectUrl = "/oauth2/authorize?response_type=code&client_id=" +
//                                authRequest.getClientId() + "&redirect_uri=" + authRequest.getRedirectUri() +
//                                "&scope=" + (authRequest.getScope() != null ? authRequest.getScope() : "read");
//            if (authRequest.getState() != null) {
//                redirectUrl += "&state=" + authRequest.getState();
//            }
//            if (authRequest.getCodeChallenge() != null) {
//                redirectUrl += "&code_challenge=" + authRequest.getCodeChallenge();
//            }
//            if (authRequest.getCodeChallengeMethod() != null) {
//                redirectUrl += "&code_challenge_method=" + authRequest.getCodeChallengeMethod();
//            }
//            return "redirect:" + redirectUrl;
//        }
//
//        return "redirect:/";
//    }

    // Helper methods

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateClientId() {
        return "client_" + generateSecureToken().substring(0, 16);
    }

    private String generateClientSecret() {
        return generateSecureToken();
    }

    private boolean isValidRedirectUri(String uri) {
        try {
            java.net.URI parsedUri = java.net.URI.create(uri);
            String scheme = parsedUri.getScheme();
            
            // Allow http for localhost development, https for production, and custom schemes for native apps
            if ("https".equals(scheme)) {
                return true;
            }
            if ("http".equals(scheme)) {
                String host = parsedUri.getHost();
                return "localhost".equals(host) || "127.0.0.1".equals(host) || host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.");
            }
            // Allow custom schemes for native apps (e.g., vscode://...)
            return scheme != null && !scheme.isEmpty() && !scheme.equals("javascript");
        } catch (Exception e) {
            return false;
        }
    }

    // Inner classes for data storage

    public static class AuthorizationRequest {
        private String clientId;
        private String redirectUri;
        private String responseType;
        private String scope;
        private String state;
        private String codeChallenge;
        private String codeChallengeMethod;

        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        public String getResponseType() { return responseType; }
        public void setResponseType(String responseType) { this.responseType = responseType; }
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        public String getState() { return state; }
        public void setState(String state) { this.state = state; }
        public String getCodeChallenge() { return codeChallenge; }
        public void setCodeChallenge(String codeChallenge) { this.codeChallenge = codeChallenge; }
        public String getCodeChallengeMethod() { return codeChallengeMethod; }
        public void setCodeChallengeMethod(String codeChallengeMethod) { this.codeChallengeMethod = codeChallengeMethod; }
    }

    public static class AuthorizationCodeInfo {
        private String code;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String userId;
        private String firebaseToken;
        private String codeChallenge;
        private String codeChallengeMethod;
        private long expiresAt;

        // Getters and setters
        public String getCode() { return code; }
        public void setCode(String code) { this.code = code; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        public String getState() { return state; }
        public void setState(String state) { this.state = state; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getFirebaseToken() { return firebaseToken; }
        public void setFirebaseToken(String firebaseToken) { this.firebaseToken = firebaseToken; }
        public String getCodeChallenge() { return codeChallenge; }
        public void setCodeChallenge(String codeChallenge) { this.codeChallenge = codeChallenge; }
        public String getCodeChallengeMethod() { return codeChallengeMethod; }
        public void setCodeChallengeMethod(String codeChallengeMethod) { this.codeChallengeMethod = codeChallengeMethod; }
        public long getExpiresAt() { return expiresAt; }
        public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    }
}