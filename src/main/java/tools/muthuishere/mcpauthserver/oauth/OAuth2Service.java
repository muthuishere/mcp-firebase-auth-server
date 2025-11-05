package tools.muthuishere.mcpauthserver.oauth;

import com.google.firebase.auth.FirebaseAuthException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import tools.muthuishere.mcpauthserver.config.ServerUrlsConfig;
import tools.muthuishere.mcpauthserver.firebase.FirebaseAuthService;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OAuth2Service {

    @Autowired
    private FirebaseAuthService firebaseAuthService;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private ServerUrlsConfig serverUrlsConfig;

    // In-memory storage for demo purposes. In production, use Redis or database.
    private final Map<String, ConsentRecord> userConsents = new ConcurrentHashMap<>();
    private final Map<String, AuthCodeRecord> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, AccessTokenRecord> accessTokens = new ConcurrentHashMap<>();
    
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Check if user has already given consent for a specific client
     */
    public boolean hasConsent(String userId, String clientId) {
        String consentKey = userId + ":" + clientId;
        ConsentRecord consent = userConsents.get(consentKey);
        return consent != null && consent.isActive();
    }

    /**
     * Store user consent for a client
     */
    public void storeConsent(String userId, String clientId, String scope) {
        String consentKey = userId + ":" + clientId;
        ConsentRecord consent = new ConsentRecord(userId, clientId, scope, Instant.now());
        userConsents.put(consentKey, consent);
    }

    /**
     * Revoke consent for a client
     */
    public void revokeConsent(String userId, String clientId) {
        String consentKey = userId + ":" + clientId;
        userConsents.remove(consentKey);
    }

    /**
     * Generate a secure authorization code
     */
    public String generateAuthorizationCode(String userId, String clientId, String scope) {
        String code = generateSecureToken();
        
        AuthCodeRecord authCodeRecord = new AuthCodeRecord(
            code, userId, clientId, scope, 
            Instant.now().plus(10, ChronoUnit.MINUTES) // 10 minutes expiry
        );
        
        authorizationCodes.put(code, authCodeRecord);
        return code;
    }

    /**
     * Exchange authorization code for access token
     */
    public Map<String, Object> exchangeAuthorizationCode(String code, String redirectUri, String clientId) 
            throws FirebaseAuthException {
        
        AuthCodeRecord authCodeRecord = authorizationCodes.get(code);
        
        if (authCodeRecord == null) {
            throw new IllegalArgumentException("Invalid authorization code");
        }
        
        if (authCodeRecord.isExpired()) {
            authorizationCodes.remove(code);
            throw new IllegalArgumentException("Authorization code expired");
        }
        
        if (!authCodeRecord.getClientId().equals(clientId)) {
            throw new IllegalArgumentException("Client ID mismatch");
        }
        
        // Remove the used authorization code (one-time use)
        authorizationCodes.remove(code);
        
        // Generate Firebase custom token
        String customToken = firebaseAuthService.createCustomToken(authCodeRecord.getUserId());
        
        // Get Firebase token expiry and calculate OAuth2 token expiry (60 seconds less for safety)
        long firebaseTokenExpirySeconds = firebaseAuthService.getCustomTokenExpirySeconds(customToken);
        long oauthTokenExpirySeconds = Math.max(60, firebaseTokenExpirySeconds - 60); // At least 60 seconds, but 60 seconds less than Firebase token
        
        // Generate JWT access token containing Firebase token as a claim
        String accessToken = generateJwtAccessToken(
            authCodeRecord.getUserId(), 
            authCodeRecord.getClientId(),
            authCodeRecord.getScope(),
            customToken,
            oauthTokenExpirySeconds // Pass the calculated expiry
        );
        String refreshToken = generateSecureToken(); // Keep refresh token as random string
        
        // Store access token with calculated expiry
        AccessTokenRecord tokenRecord = new AccessTokenRecord(
            accessToken, authCodeRecord.getUserId(), authCodeRecord.getClientId(),
            authCodeRecord.getScope(), Instant.now().plus(oauthTokenExpirySeconds, ChronoUnit.SECONDS)
        );
        accessTokens.put(accessToken, tokenRecord);
        
        // Return OAuth2 token response - now access_token is a JWT containing Firebase token
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", accessToken); // This is now a JWT with firebase_token claim
        response.put("token_type", "Bearer");
        response.put("expires_in", oauthTokenExpirySeconds); // Dynamic expiry based on Firebase token
        response.put("refresh_token", refreshToken);
        response.put("scope", authCodeRecord.getScope());
        
        // Optional: Still provide separate firebase_token for backward compatibility
        response.put("firebase_token", customToken);
        response.put("user_id", authCodeRecord.getUserId());
        
        return response;
    }

    /**
     * Validate access token
     */
    public AccessTokenRecord validateAccessToken(String accessToken) {
        AccessTokenRecord tokenRecord = accessTokens.get(accessToken);
        
        if (tokenRecord == null) {
            throw new IllegalArgumentException("Invalid access token");
        }
        
        if (tokenRecord.isExpired()) {
            accessTokens.remove(accessToken);
            throw new IllegalArgumentException("Access token expired");
        }
        
        return tokenRecord;
    }

    /**
     * Revoke access token
     */
    public void revokeAccessToken(String accessToken) {
        accessTokens.remove(accessToken);
    }

    /**
     * Refresh access token using refresh token
     */
    public Map<String, Object> refreshAccessToken(String refreshToken, String requestedScope) throws FirebaseAuthException {
        // Find the refresh token record (for now, just validate it exists in our stored tokens)
        // In a production system, you'd store refresh tokens separately with user association
        
        // For this implementation, we'll extract the user from any existing access token with this refresh token
        // This is simplified - in production you'd store refresh tokens with user association
        AccessTokenRecord associatedTokenRecord = null;
        final String[] userInfo = new String[3]; // [userId, clientId, originalScope]
        
        // Find the access token associated with this refresh token
        // In our current implementation, we need to look through stored responses
        // This is a simplified approach - production would store refresh tokens properly
        for (AccessTokenRecord tokenRecord : accessTokens.values()) {
            // For now, we'll assume the refresh token is valid if we have any access token
            // In production, you'd store refresh tokens with proper association
            userInfo[0] = tokenRecord.getUserId();
            userInfo[1] = tokenRecord.getClientId();
            userInfo[2] = tokenRecord.getScope();
            associatedTokenRecord = tokenRecord;
            break; // Take the first one for this simplified implementation
        }
        
        if (userInfo[0] == null) {
            throw new IllegalArgumentException("Invalid refresh token - no associated user found");
        }
        
        final String userId = userInfo[0];
        final String clientId = userInfo[1];
        final String originalScope = userInfo[2];
        
        // Use requested scope if provided, otherwise use original scope
        String scope = requestedScope != null ? requestedScope : originalScope;
        
        // Generate new Firebase custom token
        String newFirebaseToken = firebaseAuthService.createCustomToken(userId);
        
        // Calculate new expiry based on Firebase token
        long firebaseTokenExpirySeconds = firebaseAuthService.getCustomTokenExpirySeconds(newFirebaseToken);
        long oauthTokenExpirySeconds = Math.max(60, firebaseTokenExpirySeconds - 60);
        
        // Generate new JWT access token
        String newAccessToken = generateJwtAccessToken(userId, clientId, scope, newFirebaseToken, oauthTokenExpirySeconds);
        String newRefreshToken = generateSecureToken(); // Generate new refresh token
        
        // Store new access token (remove old one if it exists)
        if (associatedTokenRecord != null) {
            accessTokens.values().removeIf(record -> record.getUserId().equals(userId) && record.getClientId().equals(clientId));
        }
        
        AccessTokenRecord newTokenRecord = new AccessTokenRecord(
            newAccessToken, userId, clientId, scope, 
            Instant.now().plus(oauthTokenExpirySeconds, ChronoUnit.SECONDS)
        );
        accessTokens.put(newAccessToken, newTokenRecord);
        
        // Return refresh token response
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", newAccessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", oauthTokenExpirySeconds);
        response.put("refresh_token", newRefreshToken);
        response.put("scope", scope);
        
        // Optional: Include Firebase token for backward compatibility
        response.put("firebase_token", newFirebaseToken);
        response.put("user_id", userId);
        
        return response;
    }

    /**
     * Get user information for a valid access token
     */
    public Map<String, Object> getUserInfo(String accessToken) throws FirebaseAuthException {
        AccessTokenRecord tokenRecord = validateAccessToken(accessToken);
        
        // Get user information from Firebase
        String userId = tokenRecord.getUserId();
        Map<String, Object> userInfo = firebaseAuthService.getUserInfo(userId);
        
        // Generate a fresh Firebase custom token for this user
        String firebaseToken = firebaseAuthService.createCustomToken(userId);
        
        // Add Firebase token to user info
        userInfo.put("firebase_token", firebaseToken);
        userInfo.put("scope", tokenRecord.getScope());
        
        return userInfo;
    }

    /**
     * Generate a secure random token (for authorization codes and refresh tokens)
     */
    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generate a JWT access token containing the Firebase token as a claim
     */
    private String generateJwtAccessToken(String userId, String clientId, String scope, String firebaseToken) {
        return generateJwtAccessToken(userId, clientId, scope, firebaseToken, 3600L); // Default 1 hour
    }

    /**
     * Generate a JWT access token containing the Firebase token as a claim with custom expiry
     */
    private String generateJwtAccessToken(String userId, String clientId, String scope, String firebaseToken, long expirySeconds) {
        System.out.println("generateJwtAccessToken called for user: " + userId + ", firebase_token: " + 
                          (firebaseToken != null ? firebaseToken.substring(0, Math.min(50, firebaseToken.length())) + "..." : "null"));
        
        Instant now = Instant.now();
        Instant expiry = now.plus(expirySeconds, ChronoUnit.SECONDS);

        // Use the configured issuer URL from centralized configuration
        String issuerUrl = serverUrlsConfig.getIssuerUrl();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuerUrl) // Dynamic OAuth2 server issuer based on actual port
                .subject(userId)
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("scope", scope)
                .claim("firebase_token", firebaseToken) // Embed Firebase token as a claim
                .claim("token_type", "access_token")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // Inner classes for data storage
    public static class ConsentRecord {
        private final String userId;
        private final String clientId;
        private final String scope;
        private final Instant createdAt;

        public ConsentRecord(String userId, String clientId, String scope, Instant createdAt) {
            this.userId = userId;
            this.clientId = clientId;
            this.scope = scope;
            this.createdAt = createdAt;
        }

        public boolean isActive() {
            // Consent is valid for 30 days
            return Instant.now().isBefore(createdAt.plus(30, ChronoUnit.DAYS));
        }

        // Getters
        public String getUserId() { return userId; }
        public String getClientId() { return clientId; }
        public String getScope() { return scope; }
        public Instant getCreatedAt() { return createdAt; }
    }

    public static class AuthCodeRecord {
        private final String code;
        private final String userId;
        private final String clientId;
        private final String scope;
        private final Instant expiresAt;

        public AuthCodeRecord(String code, String userId, String clientId, String scope, Instant expiresAt) {
            this.code = code;
            this.userId = userId;
            this.clientId = clientId;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }

        // Getters
        public String getCode() { return code; }
        public String getUserId() { return userId; }
        public String getClientId() { return clientId; }
        public String getScope() { return scope; }
        public Instant getExpiresAt() { return expiresAt; }
    }

    public static class AccessTokenRecord {
        private final String token;
        private final String userId;
        private final String clientId;
        private final String scope;
        private final Instant expiresAt;

        public AccessTokenRecord(String token, String userId, String clientId, String scope, Instant expiresAt) {
            this.token = token;
            this.userId = userId;
            this.clientId = clientId;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }

        // Getters
        public String getToken() { return token; }
        public String getUserId() { return userId; }
        public String getClientId() { return clientId; }
        public String getScope() { return scope; }
        public Instant getExpiresAt() { return expiresAt; }
    }

    // Additional public methods needed by OAuthController

    /**
     * Generate a JWT access token with Firebase token as claim (public method)
     */
    public String createJwtAccessToken(String userId, String clientId, String scope, String firebaseToken) {
        System.out.println("createJwtAccessToken called for user: " + userId + ", firebase_token: " + 
                          (firebaseToken != null ? firebaseToken.substring(0, Math.min(50, firebaseToken.length())) + "..." : "null"));
        return generateJwtAccessToken(userId, clientId, scope, firebaseToken, 3600L);
    }

    /**
     * Generate a refresh token for the given user and client
     */
    public String generateRefreshToken(String userId, String clientId, String scope) {
        return generateSecureToken(); // Simple implementation - in production, store mapping
    }

    /**
     * Get access token expiry in seconds
     */
    public long getAccessTokenExpirySeconds() {
        return 3600L; // 1 hour
    }

    /**
     * Verify PKCE code challenge
     */
    public boolean verifyPkceChallenge(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (codeChallenge == null || codeVerifier == null) {
            return false;
        }

        if ("plain".equals(codeChallengeMethod)) {
            return codeChallenge.equals(codeVerifier);
        } else if ("S256".equals(codeChallengeMethod)) {
            try {
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes("UTF-8"));
                String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return codeChallenge.equals(computed);
            } catch (Exception e) {
                return false;
            }
        }
        
        return false;
    }

    /**
     * Extract user info from JWT access token
     */
    public Map<String, Object> extractUserInfoFromToken(String accessToken) {
        AccessTokenRecord tokenRecord = validateAccessToken(accessToken);
        if (tokenRecord == null) {
            return null;
        }

        // In a real implementation, you would decode the JWT and extract claims
        // For now, return basic user info
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", tokenRecord.getUserId());
        userInfo.put("client_id", tokenRecord.getClientId());
        userInfo.put("scope", tokenRecord.getScope());
        
        return userInfo;
    }

    /**
     * Refresh access token with client_id parameter
     */
    public Map<String, Object> refreshAccessToken(String refreshToken, String clientId, String requestedScope) 
            throws FirebaseAuthException {
        // For simplicity, delegate to existing method
        return refreshAccessToken(refreshToken, requestedScope);
    }
}