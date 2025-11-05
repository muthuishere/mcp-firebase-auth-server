//package tools.muthuishere.mcpauthserver.service;
//
//import org.springframework.stereotype.Service;
//import java.util.Map;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.UUID;
//
//@Service
//public class ClientRegistrationService {
//
//    private final Map<String, RegisteredClient> registeredClients = new ConcurrentHashMap<>();
//
//    public static class RegisteredClient {
//        private String clientId;
//        private String clientSecret;
//        private String[] redirectUris;
//        private long issuedAt;
//        private String scope;
//
//        public RegisteredClient(String clientId, String clientSecret, String[] redirectUris, String scope) {
//            this.clientId = clientId;
//            this.clientSecret = clientSecret;
//            this.redirectUris = redirectUris;
//            this.scope = scope;
//            this.issuedAt = System.currentTimeMillis() / 1000;
//        }
//
//        // Getters
//        public String getClientId() { return clientId; }
//        public String getClientSecret() { return clientSecret; }
//        public String[] getRedirectUris() { return redirectUris; }
//        public long getIssuedAt() { return issuedAt; }
//        public String getScope() { return scope; }
//    }
//
//    public RegisteredClient registerClient(String[] redirectUris, String scope) {
//        String clientId = "mcp-client-" + UUID.randomUUID().toString().substring(0, 8);
//        String clientSecret = "secret-" + UUID.randomUUID().toString();
//
//        RegisteredClient client = new RegisteredClient(clientId, clientSecret, redirectUris, scope != null ? scope : "read:email");
//        registeredClients.put(clientId, client);
//
//        return client;
//    }
//
//    public RegisteredClient getClient(String clientId) {
//        return registeredClients.get(clientId);
//    }
//
//    public boolean validateClient(String clientId, String clientSecret) {
//        RegisteredClient client = registeredClients.get(clientId);
//        return client != null && client.getClientSecret().equals(clientSecret);
//    }
//
//    public boolean isValidRedirectUri(String clientId, String redirectUri) {
//        RegisteredClient client = registeredClients.get(clientId);
//        if (client == null) return false;
//
//        for (String uri : client.getRedirectUris()) {
//            if (uri.equals(redirectUri)) {
//                return true;
//            }
//        }
//        return false;
//    }
//}