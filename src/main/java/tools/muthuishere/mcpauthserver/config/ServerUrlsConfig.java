package tools.muthuishere.mcpauthserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Centralized configuration for all server URLs used throughout the application.
 * 
 * Only 2 environment variables are needed:
 * - MCP_AUTH_SERVER_URL: Base URL of this OAuth2 authorization server (default: http://localhost:9000)
 * - MCP_SERVER_BASE_URL: Base URL of the MCP resource server (default: http://localhost:8080)
 * 
 * All specific endpoints are automatically derived from these base URLs.
 */
@Component
@ConfigurationProperties(prefix = "app.urls")
public class ServerUrlsConfig {
    
    // Base URLs (configurable via environment variables)
    private String authServerBaseUrl = "http://localhost:9000";
    private String mcpResourceBaseUrl = "http://localhost:8080/mcp";
    
    // Fixed redirect URLs (not configurable to maintain security)
    private String defaultClientRedirectUrl = "http://localhost:3000/callback";
    private String testClientRedirectUrl = "http://localhost:8080/callback";
    
    // Getters and Setters
    public String getAuthServerBaseUrl() {
        return authServerBaseUrl;
    }
    
    public void setAuthServerBaseUrl(String authServerBaseUrl) {
        this.authServerBaseUrl = authServerBaseUrl;
    }
    
    public String getMcpResourceBaseUrl() {
        return mcpResourceBaseUrl;
    }
    
    public void setMcpResourceBaseUrl(String mcpResourceBaseUrl) {
        this.mcpResourceBaseUrl = mcpResourceBaseUrl;
    }
    
    public String getDefaultClientRedirectUrl() {
        return defaultClientRedirectUrl;
    }
    
    public void setDefaultClientRedirectUrl(String defaultClientRedirectUrl) {
        this.defaultClientRedirectUrl = defaultClientRedirectUrl;
    }
    
    public String getTestClientRedirectUrl() {
        return testClientRedirectUrl;
    }
    
    public void setTestClientRedirectUrl(String testClientRedirectUrl) {
        this.testClientRedirectUrl = testClientRedirectUrl;
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
    
    public String getMcpResourceUrl() {
        return mcpResourceBaseUrl + "/";
    }
}