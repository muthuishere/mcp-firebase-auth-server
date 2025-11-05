package tools.muthuishere.mcpauthserver.authflow;

public class ConsentRequest {
    
    private boolean approved;
    private String clientId;
    private String scope;

    // Default constructor
    public ConsentRequest() {}

    // Constructor
    public ConsentRequest(boolean approved, String clientId, String scope) {
        this.approved = approved;
        this.clientId = clientId;
        this.scope = scope;
    }

    // Getters and Setters
    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}