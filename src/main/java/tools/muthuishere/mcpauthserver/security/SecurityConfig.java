package tools.muthuishere.mcpauthserver.security;


import com.google.firebase.auth.FirebaseAuth;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final FirebaseAuth firebaseAuth;

    public SecurityConfig(FirebaseAuth firebaseAuth) {
        this.firebaseAuth = firebaseAuth;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for API endpoints and OAuth endpoints but keep for form submissions
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/**", "/oauth2/token", "/oauth2/register", "/oauth2/health","/oauth/token","/oauth2/refresh", "/oauth/**")
                .csrfTokenRepository(org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // Configure CORS
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/", "/login", "/error/**", "/api/config").permitAll()
                .requestMatchers("/css/**", "/js/**", "/images/**", "/static/**").permitAll()
                .requestMatchers("/favicon.ico", "/robots.txt").permitAll()
                            .requestMatchers("/oauth2/**").permitAll()
                // OAuth2 and well-known endpoints
//                .requestMatchers("/oauth2/authorize",oauth2/register"," "/oauth2/token", "/oauth2/consent","/oauth2/refresh").permitAll()

//                .requestMatchers("/oauth/authorize", "/oauth/token", "/oauth2/register").permitAll()
//                .requestMatchers("/oauth/**").permitAll()
                .requestMatchers("/.well-known/**").permitAll()
                
                // Auth and login endpoints (including GitHub-style OAuth)
                .requestMatchers("/auth/**", "/login/**").permitAll()
                
                // API endpoints require authentication for session management
                .requestMatchers("/api/auth/**").permitAll()
                
                // Actuator endpoints
                .requestMatchers("/actuator/health").permitAll()
//                .requestMatchers("/actuator/**").hasRole("ADMIN")
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            
            // Configure session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
            )
            
            // Configure headers for security
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.deny())
                .contentTypeOptions(contentTypeOptions -> {})
                .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                )
            )
            
            // Disable form login since we're using Firebase
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())

            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "MCP_AUTHORIZATION_SERVER_SESSIONID")
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

//    @Bean
//    JWKSource<SecurityContext> jwkSource() {
//        RSAKey rsaKey = Jwks.generateRsa();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
//    }
}