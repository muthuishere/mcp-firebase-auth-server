package tools.muthuishere.mcpauthserver.oauth;

import java.util.List;

/**
 * Represents a dynamically registered OAuth2 client
 * Used for storing client registration information
 */
public class RegisteredClientInfo {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private List<String> redirectUris;
    private String tokenEndpointAuthMethod;
    private List<String> grantTypes;
    private List<String> responseTypes;
    private String scope;
    private long createdAt;

    // Default constructor
    public RegisteredClientInfo() {}

    // Constructor with basic info
    public RegisteredClientInfo(String clientId, String clientSecret, String clientName, List<String> redirectUris) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.createdAt = System.currentTimeMillis();
    }

    // Getters and Setters
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
}