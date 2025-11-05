package tools.muthuishere.mcpauthserver.authflow;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthRequest {
    
    @JsonProperty("idToken")
    private String idToken;
    
    @JsonProperty("refreshToken") 
    private String refreshToken;
    
    @JsonProperty("email")
    private String email;
    
    @JsonProperty("password")
    private String password;

    // Default constructor
    public AuthRequest() {}

    // Constructor
    public AuthRequest(String idToken) {
        this.idToken = idToken;
    }

    // Getters and Setters
    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}