package tools.muthuishere.mcpauthserver.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.muthuishere.mcpauthserver.config.ServerUrlsConfig;

import java.io.IOException;

/**
 * Custom AuthenticationEntryPoint for MCP Authorization flow
 * Returns WWW-Authenticate header with authorization server details when JWT is invalid/missing
 */
@Component
public class McpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Autowired
    private ServerUrlsConfig serverUrlsConfig;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
        
        // Set WWW-Authenticate header as per MCP specification
        String wwwAuthenticate = String.format(
            "Bearer realm=\"MCP\", " +
            "authorization_uri=\"%s\", " +
            "token_uri=\"%s\", " +
            "scope=\"mcp:basic\"",
            serverUrlsConfig.getAuthorizationEndpoint(), serverUrlsConfig.getTokenEndpoint()
        );
        
        response.setHeader("WWW-Authenticate", wwwAuthenticate);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        
        // Return JSON error response
        String errorResponse = """
            {
                "error": "unauthorized",
                "error_description": "Valid JWT token required. Use authorization_uri to obtain access token.",
                "authorization_uri": "%s",
                "token_uri": "%s"
            }
            """.formatted(serverUrlsConfig.getAuthorizationEndpoint(), serverUrlsConfig.getTokenEndpoint());
        
        response.getWriter().write(errorResponse);
    }
}