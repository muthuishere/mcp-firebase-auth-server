package tools.muthuishere.mcpauthserver.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom JWT Decoder for Firebase tokens
 * Validates Firebase ID tokens and converts them to Spring Security JWT format
 */
@Component
public class FirebaseJwtDecoder implements JwtDecoder {

    @Autowired
    private FirebaseAuth firebaseAuth;

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            // Verify the Firebase ID token
            FirebaseToken firebaseToken = firebaseAuth.verifyIdToken(token);
            
            // Extract claims from Firebase token
            Map<String, Object> claims = new HashMap<>(firebaseToken.getClaims());
            
            // Ensure required claims are present
            claims.put("sub", firebaseToken.getUid());
            claims.put("iss", firebaseToken.getIssuer());
//            claims.put("aud", firebaseToken.getAudience());
            claims.put("email", firebaseToken.getEmail());
            claims.put("email_verified", firebaseToken.isEmailVerified());
            
            // Get expiration and issued at times
            Instant issuedAt = Instant.ofEpochSecond((Long) claims.getOrDefault("iat", System.currentTimeMillis() / 1000));
            Instant expiresAt = Instant.ofEpochSecond((Long) claims.get("exp"));
            
            // Create JWT headers
            Map<String, Object> headers = new HashMap<>();
            headers.put("typ", "JWT");
            headers.put("alg", "RS256");
            
            // Create Spring Security JWT
            return new Jwt(
                token,
                issuedAt,
                expiresAt,
                headers,
                claims
            );
            
        } catch (FirebaseAuthException e) {
            throw new JwtException("Invalid Firebase token: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new JwtException("Failed to decode Firebase token: " + e.getMessage(), e);
        }
    }
}