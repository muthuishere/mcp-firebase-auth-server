package tools.muthuishere.mcpauthserver.config;


import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@Configuration

public class FirebaseConfig {


    @Value("${firebase.service-account-key}")
    private String serviceAccountKey;


    @Value("${firebase.project-id}")
    private String projectId;

    @Bean
    public FirebaseApp firebaseApp() throws IOException {

         FirebaseApp firebaseApp;

        if (serviceAccountKey != null && !serviceAccountKey.trim().isEmpty() && !serviceAccountKey.contains(":::")) {
            // Parse service account key JSON from properties
            ByteArrayInputStream serviceAccountStream = new ByteArrayInputStream(serviceAccountKey.getBytes());
            GoogleCredentials credentials = GoogleCredentials.fromStream(serviceAccountStream);

            // Configure Firebase options
            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(credentials)
                    .setProjectId(projectId)
                    .build();

            // Initialize Firebase App
            if (FirebaseApp.getApps().isEmpty()) {
                firebaseApp = FirebaseApp.initializeApp(options);
            } else {
                firebaseApp = FirebaseApp.getInstance();
            }

            return firebaseApp;
        }

        throw new IllegalStateException("Firebase service account key not set");


//        FirebaseOptions options = FirebaseOptions.builder()
//                .setCredentials(GoogleCredentials.fromStream(serviceAccount.getInputStream()))
//                .build();
//        return FirebaseApp.initializeApp(options);
    }



    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp app) {
        return FirebaseAuth.getInstance(app);
    }
}
