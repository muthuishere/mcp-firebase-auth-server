package tools.muthuishere.mcpauthserver.oauth;

import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.muthuishere.mcpauthserver.config.ServerUrlsConfig;

@RestController
public class OAuth2MetadataController {

    @Autowired
    private ServerUrlsConfig serverUrlsConfig;

    @Value("${firebase.project-id}")
    private String projectId;

    /**
     * OAuth2 Authorization Server Metadata endpoint
     * As per RFC 8414: https://tools.ietf.org/html/rfc8414
     */
    @GetMapping(
        value = "/.well-known/openid-configuration",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> wellKnownConfiguration() {
        String issuer = serverUrlsConfig.getIssuerUrl();

        Map<String, Object> config = new java.util.HashMap<>();
        config.put("issuer", issuer);
        config.put(
            "authorization_endpoint",
            serverUrlsConfig.getAuthorizationEndpoint()
        );
        config.put("token_endpoint", serverUrlsConfig.getTokenEndpoint());
        config.put("jwks_uri", serverUrlsConfig.getJwksUri());
        config.put("response_types_supported", new String[] { "code" });
        config.put(
            "grant_types_supported",
            new String[] { "authorization_code", "refresh_token" }
        );
        config.put("subject_types_supported", new String[] { "public" });
        config.put(
            "id_token_signing_alg_values_supported",
            new String[] { "RS256" }
        );
        config.put(
            "scopes_supported",
            new String[] { "openid", "profile", "email", "firebase" }
        );
        config.put(
            "token_endpoint_auth_methods_supported",
            new String[] { "client_secret_basic", "client_secret_post", "none" }
        );
        config.put(
            "claims_supported",
            new String[] {
                "sub",
                "aud",
                "iss",
                "exp",
                "iat",
                "email",
                "email_verified",
                "firebase",
            }
        );

        return ResponseEntity.ok(config);
    }

    /**
     * JSON Web Key Set endpoint for token verification
     */
    @GetMapping(
        value = "/oauth2/jwks",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> jwks() {
        // For Firebase integration, we typically don't need to provide our own JWKS
        // since we're acting as a proxy. However, for completeness, we provide a minimal response.
        Map<String, Object> jwks = Map.of(
            "keys",
            new Object[] {
                Map.of(
                    "kty",
                    "RSA",
                    "use",
                    "sig",
                    "kid",
                    "firebase-auth-proxy-key",
                    "alg",
                    "RS256",
                    "n",
                    "placeholder-for-actual-key",
                    "e",
                    "AQAB"
                ),
            }
        );

        return ResponseEntity.ok(jwks);
    }

    /**
     * OAuth 2.0 Authorization Server Metadata
     * As per RFC 8414: https://tools.ietf.org/html/rfc8414
     */
    @GetMapping(
        value = "/.well-known/oauth-authorization-server",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> authorizationServerMetadata() {
        String baseUrl = serverUrlsConfig.getIssuerUrl();
        Map<String, Object> metadata = new java.util.HashMap<>();
        metadata.put("issuer", baseUrl);
        metadata.put(
            "authorization_endpoint",
            serverUrlsConfig.getAuthorizationEndpoint()
        );
        metadata.put("token_endpoint", serverUrlsConfig.getTokenEndpoint());
        metadata.put("jwks_uri", baseUrl + "/.well-known/jwks.json");
        metadata.put("scopes_supported", new String[] { "read:email" });
        metadata.put(
            "response_types_supported",
            new String[] { "code", "token" }
        );
        metadata.put(
            "grant_types_supported",
            new String[] { "authorization_code", "refresh_token" }
        );
        metadata.put("subject_types_supported", new String[] { "public" });
        metadata.put(
            "id_token_signing_alg_values_supported",
            new String[] { "RS256" }
        );
        metadata.put(
            "token_endpoint_auth_methods_supported",
            new String[] { "client_secret_basic", "client_secret_post", "none" }
        );
        metadata.put("revocation_endpoint", baseUrl + "/oauth2/revoke");
        metadata.put("introspection_endpoint", baseUrl + "/oauth2/introspect");
        metadata.put(
            "registration_endpoint",
            serverUrlsConfig.getRegistrationEndpoint()
        );
        metadata.put(
            "code_challenge_methods_supported",
            new String[] { "S256", "plain" }
        );

        return ResponseEntity.ok(metadata);
    }

    /**
     * JWKS endpoint for JWT token verification
     */
    @GetMapping(
        value = "/.well-known/jwks.json",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> publicJwks() {
        // This would normally contain the public keys for JWT verification
        // For Firebase tokens, this redirects to Firebase's JWKS
        Map<String, Object> jwks = Map.of(
            "keys",
            new Object[] {
                Map.of(
                    "kty",
                    "RSA",
                    "use",
                    "sig",
                    "kid",
                    "firebase-key-id",
                    "alg",
                    "RS256",
                    "n",
                    "example-modulus",
                    "e",
                    "AQAB"
                ),
            },
            "firebase_jwks_uri",
            "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
        );

        return ResponseEntity.ok(jwks);
    }

    /**
     * Health check endpoint for the OAuth2 server
     */
    @GetMapping(
        value = "/oauth2/health",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = Map.of(
            "status",
            "UP",
            "service",
            "Firebase Auth Proxy",
            "firebase_project",
            projectId,
            "timestamp",
            System.currentTimeMillis()
        );

        return ResponseEntity.ok(health);
    }

    /**
     * Simple health check endpoint
     */
    @GetMapping(value = "/api/health", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> apiHealth() {
        return ResponseEntity.ok("ok");
    }

    /**
     * Configuration endpoint for frontend applications
     * Provides all configurable URLs for JavaScript clients
     */
    @GetMapping(
        value = "/config/urls",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> urlsConfig() {
        Map<String, Object> config = new java.util.HashMap<>();
        config.put(
            "authServerBaseUrl",
            serverUrlsConfig.getAuthServerBaseUrl()
        );
        config.put(
            "defaultClientRedirectUrl",
            serverUrlsConfig.getDefaultClientRedirectUrl()
        );
        config.put(
            "authorizationEndpoint",
            serverUrlsConfig.getAuthorizationEndpoint()
        );
        config.put("tokenEndpoint", serverUrlsConfig.getTokenEndpoint());
        config.put(
            "refreshTokenEndpoint",
            serverUrlsConfig.getRefreshTokenEndpoint()
        );
        config.put(
            "registrationEndpoint",
            serverUrlsConfig.getRegistrationEndpoint()
        );
        config.put("userInfoEndpoint", serverUrlsConfig.getUserInfoEndpoint());
        config.put("jwksUri", serverUrlsConfig.getJwksUri());
        config.put(
            "wellKnownEndpoint",
            serverUrlsConfig.getWellKnownEndpoint()
        );

        return ResponseEntity.ok(config);
    }
}
