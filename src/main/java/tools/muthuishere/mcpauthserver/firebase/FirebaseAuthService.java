package tools.muthuishere.mcpauthserver.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class FirebaseAuthService {

    @Autowired
    private FirebaseAuth firebaseAuth;

    @Value("${firebase.project-id}")
    private String projectId;

    @Value("${firebase.apiKey}")
    private String apiKey;

    /**
     * Verify Firebase ID token
     */
    public FirebaseToken verifyToken(String idToken) throws FirebaseAuthException {
        if (idToken == null || idToken.trim().isEmpty()) {
            throw new IllegalArgumentException("ID token cannot be null or empty");
        }

        return firebaseAuth.verifyIdToken(idToken);
    }

    /**
     * Create a custom token for a user
     */
    public String createCustomToken(String uid) throws FirebaseAuthException {
        return firebaseAuth.createCustomToken(uid);
    }

    /**
     * Create a custom token with additional claims
     */
    public String createCustomToken(String uid, java.util.Map<String, Object> claims) throws FirebaseAuthException {
        return firebaseAuth.createCustomToken(uid, claims);
    }

    /**
     * Get Firebase project ID
     */
    public String getProjectId() {
        return projectId;
    }

    /**
     * Get Firebase API Key
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     * Validate Firebase token and extract user information
     */
    public FirebaseToken validateAndDecodeToken(String idToken) throws FirebaseAuthException {
        FirebaseToken decodedToken = verifyToken(idToken);

        // Additional validation can be added here
        if (decodedToken.getUid() == null || decodedToken.getUid().isEmpty()) {
            throw new IllegalArgumentException("Token does not contain valid user ID");
        }

        return decodedToken;
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(FirebaseToken token) {
        // Firebase tokens have expiration time in their claims
        Long exp = (Long) token.getClaims().get("exp");
        return exp != null && System.currentTimeMillis() / 1000 > exp;
    }

    /**
     * Get user claims from token
     */
    public java.util.Map<String, Object> getUserClaims(FirebaseToken token) {
        return token.getClaims();
    }

    /**
     * Get expiry time in seconds from Firebase custom token
     * Firebase custom tokens typically have 1 hour (3600 seconds) expiry
     */
    @SuppressWarnings("unchecked")
    public long getCustomTokenExpirySeconds(String customToken) {
        try {
            // Decode JWT without verification to get expiry
            String[] parts = customToken.split("\\.");
            if (parts.length != 3) {
                return 3600; // Default 1 hour if can't decode
            }

            // Decode payload (second part)
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            java.util.Map<String, Object> claims = mapper.readValue(payload, java.util.Map.class);

            Object exp = claims.get("exp");
            if (exp instanceof Number) {
                long expiry = ((Number) exp).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                return Math.max(0, expiry - currentTime); // Return remaining seconds
            }

            return 3600; // Default 1 hour if no exp claim
        } catch (Exception e) {
            // If we can't decode, assume 1 hour expiry
            return 3600;
        }
    }


    /**
     * Get user information by user ID
     */
    public java.util.Map<String, Object> getUserInfo(String uid) throws FirebaseAuthException {
        com.google.firebase.auth.UserRecord userRecord = firebaseAuth.getUser(uid);
        
        java.util.Map<String, Object> userInfo = new java.util.HashMap<>();
        userInfo.put("uid", userRecord.getUid());
        userInfo.put("email", userRecord.getEmail());
        userInfo.put("email_verified", userRecord.isEmailVerified());
        userInfo.put("display_name", userRecord.getDisplayName());
        userInfo.put("photo_url", userRecord.getPhotoUrl());
        userInfo.put("provider_id", userRecord.getProviderId());
        userInfo.put("disabled", userRecord.isDisabled());
        
        // Add creation and last sign-in time if available
        if (userRecord.getUserMetadata() != null) {
            userInfo.put("creation_time", userRecord.getUserMetadata().getCreationTimestamp());
            userInfo.put("last_sign_in_time", userRecord.getUserMetadata().getLastSignInTimestamp());
        }
        
        return userInfo;
    }
}