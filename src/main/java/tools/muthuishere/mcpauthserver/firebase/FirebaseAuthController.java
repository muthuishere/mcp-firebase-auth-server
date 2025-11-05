package tools.muthuishere.mcpauthserver.firebase;

import com.google.firebase.auth.FirebaseToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import tools.muthuishere.mcpauthserver.config.ServerUrlsConfig;
import tools.muthuishere.mcpauthserver.authflow.AuthRequest;
import tools.muthuishere.mcpauthserver.authflow.AuthResponse;

import jakarta.servlet.http.HttpSession;
import java.util.Map;

/**
 * Firebase Authentication Controller
 * Handles Firebase authentication and basic OAuth metadata
 * OAuth2 endpoints are handled by OAuthController
 */
@Controller
@RequestMapping
public class FirebaseAuthController {

    @Autowired
    private FirebaseAuthService firebaseAuthService;
    
    @Autowired
    private ServerUrlsConfig serverUrlsConfig;

    /**
     * Main login page
     */
    @GetMapping("/")
    public String loginPage(Model model) {
        model.addAttribute("projectId", firebaseAuthService.getProjectId());
        return "login";
    }

    /**
     * Alternative login endpoint
     */
    @GetMapping("/login")
    public String loginPageAlternate(Model model) {
        model.addAttribute("projectId", firebaseAuthService.getProjectId());
        return "login";
    }

    /**
     * OAuth login page endpoint - serves HTML for browsers
     */
    @GetMapping(value = "/login/oauth", produces = MediaType.TEXT_HTML_VALUE)
    public String loginOauth(Model model) {
        model.addAttribute("projectId", firebaseAuthService.getProjectId());
        return "login";
    }

    /**
     * OAuth server metadata endpoint for VS Code MCP Inspector discovery - serves JSON for API clients
     */
    @GetMapping(value = "/login/oauth", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> loginOauthGet() {
        Map<String, Object> metadata = Map.of(
            "issuer", serverUrlsConfig.getIssuerUrl(),
            "authorization_endpoint", serverUrlsConfig.getAuthorizationEndpoint(),
            "token_endpoint", serverUrlsConfig.getTokenEndpoint(),
            "registration_endpoint", serverUrlsConfig.getRegistrationEndpoint(),
            "response_types_supported", new String[]{"code"},
            "grant_types_supported", new String[]{"authorization_code"},
            "token_endpoint_auth_methods_supported", new String[]{"client_secret_basic", "client_secret_post", "none"},
            "scopes_supported", new String[]{"read:email"},
            "code_challenge_methods_supported", new String[]{"S256", "plain"}
        );
        
        return ResponseEntity.ok(metadata);
    }

    /**
     * OAuth login endpoint - handles OAuth authorization requests
     */
    @PostMapping("/login/oauth")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> loginOauthPost(
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state) {
        
        // Return authorization endpoint information
        Map<String, Object> response = Map.of(
            "authorization_url", serverUrlsConfig.getAuthorizationEndpoint(),
            "token_url", serverUrlsConfig.getTokenEndpoint(),
            "scope", scope != null ? scope : "read:email"
        );
        
        return ResponseEntity.ok(response);
    }

    /**
     * GitHub-style OAuth authorization endpoint - redirects to main OAuth2 authorize
     */
    @GetMapping("/login/oauth/authorize")
    public String loginOauthAuthorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", required = false, defaultValue = "read:email") String scope,
            @RequestParam(value = "state", required = false) String state) {
        
        // Redirect to main OAuth2 authorize endpoint
        String redirectUrl = "/oauth2/authorize?response_type=code&client_id=" + clientId + 
                           "&redirect_uri=" + redirectUri + "&scope=" + scope;
        if (state != null) {
            redirectUrl += "&state=" + state;
        }
        return "redirect:" + redirectUrl;
    }

    /**
     * Firebase authentication endpoint
     */
    @PostMapping("/api/auth/firebase")
    @ResponseBody
    public ResponseEntity<AuthResponse> authenticateWithFirebase(@RequestBody AuthRequest request) {
        try {
            // Verify Firebase ID token
            FirebaseToken decodedToken = firebaseAuthService.verifyToken(request.getIdToken());
            String uid = decodedToken.getUid();
            String email = decodedToken.getEmail();

            AuthResponse response = new AuthResponse();
            response.setSuccess(true);
            response.setUserId(uid);
            response.setEmail(email);
            response.setMessage("Authentication successful");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            AuthResponse response = new AuthResponse();
            response.setSuccess(false);
            response.setMessage("Authentication failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    /**
     * Session-based authentication (used by consent flow)
     */
    @PostMapping("/api/auth/session")
    @ResponseBody
    public ResponseEntity<AuthResponse> createSession(@RequestBody AuthRequest request, HttpSession session) {
        try {
            // Verify Firebase ID token
            FirebaseToken decodedToken = firebaseAuthService.verifyToken(request.getIdToken());
            String uid = decodedToken.getUid();
            String email = decodedToken.getEmail();

            // Store authenticated user in session
            session.setAttribute("authenticated_user_id", uid);
            session.setAttribute("authenticated_user_email", email);
            session.setAttribute("firebase_token", request.getIdToken()); // Store the original Firebase JWT token

            AuthResponse response = new AuthResponse();
            response.setSuccess(true);
            response.setUserId(uid);
            response.setEmail(email);
            response.setMessage("Session created successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            AuthResponse response = new AuthResponse();
            response.setSuccess(false);
            response.setMessage("Session creation failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    /**
     * GitHub-style OAuth token endpoint - forwards to main OAuth2 token endpoint
     */
    @PostMapping("/login/oauth/access_token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> loginOauthAccessToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        
        // Redirect to main OAuth2 token endpoint
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", "/oauth2/token")
                .build();
    }

    /**
     * Firebase project configuration endpoint
     */
    @GetMapping("/api/config")
    @ResponseBody
    public ResponseEntity<Map<String, String>> getConfig() {
        Map<String, String> config = Map.of(
            "projectId", firebaseAuthService.getProjectId(),
            "apiKey", firebaseAuthService.getApiKey()
        );
        return ResponseEntity.ok(config);
    }

    /**
     * General logout endpoint
     */
    @PostMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    /**
     * Error page
     */
    @GetMapping("/error")
    public String error() {
        return "error/general_error";
    }
}