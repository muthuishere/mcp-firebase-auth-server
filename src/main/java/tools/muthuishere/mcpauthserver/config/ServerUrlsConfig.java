package tools.muthuishere.mcpauthserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Centralized configuration for all server URLs used throughout the application.
 * 
 * Only 1 environment variable is needed:
 * - MCP_AUTH_SERVER_URL: Base URL of this OAuth2 authorization server (default: http://localhost:9000)
 * 
 * All specific endpoints are automatically derived from this base URL.
 */
@Component
@ConfigurationProperties(prefix = "app.urls")
public class ServerUrlsConfig {
    
    // Base URLs (configurable via environment variables)
    private String authServerBaseUrl = "http://localhost:9000";
    
    // Fixed redirect URLs (not configurable to maintain security)
    private String defaultClientRedirectUrl = "http://localhost:3000/callback";
    
    // Getters and Setters
    public String getAuthServerBaseUrl() {
        return authServerBaseUrl;
    }
    
    public void setAuthServerBaseUrl(String authServerBaseUrl) {
        this.authServerBaseUrl = authServerBaseUrl;
    }
    
    public String getDefaultClientRedirectUrl() {
        return defaultClientRedirectUrl;
    }
    
    public void setDefaultClientRedirectUrl(String defaultClientRedirectUrl) {
        this.defaultClientRedirectUrl = defaultClientRedirectUrl;
    }
    
    // Convenience methods for common OAuth2 endpoints
    public String getIssuerUrl() {
        return authServerBaseUrl;
    }
    
    public String getAuthorizationEndpoint() {
        return authServerBaseUrl + "/oauth2/authorize";
    }
    
    public String getTokenEndpoint() {
        return authServerBaseUrl + "/oauth2/token";
    }
    
    public String getRefreshTokenEndpoint() {
        return authServerBaseUrl + "/oauth2/refresh";
    }
    
    public String getRegistrationEndpoint() {
        return authServerBaseUrl + "/oauth2/register";
    }
    
    public String getUserInfoEndpoint() {
        return authServerBaseUrl + "/oauth2/userinfo";
    }
    
    public String getJwksUri() {
        return authServerBaseUrl + "/oauth2/jwks";
    }
    
    public String getWellKnownEndpoint() {
        return authServerBaseUrl + "/.well-known/oauth-authorization-server";
    }
}