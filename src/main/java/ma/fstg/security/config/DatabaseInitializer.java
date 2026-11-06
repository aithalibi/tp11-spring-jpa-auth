package ma.fstg.security.config;

import ma.fstg.security.entities.Role;
import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.RoleRepository;
import ma.fstg.security.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

/**
 * Insere les roles et les comptes de demonstration au demarrage.
 * L'operation est idempotente : relancer l'application ne duplique rien.
 */
@Configuration
public class DatabaseInitializer {

    @Bean
    CommandLineRunner init(RoleRepository roleRepo,
                           UserRepository userRepo,
                           BCryptPasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() > 0) {
                return;
            }

            Role adminRole = roleRepo.findByName("ROLE_ADMIN");
            if (adminRole == null) {
                adminRole = roleRepo.save(new Role(null, "ROLE_ADMIN"));
            }
            Role userRole = roleRepo.findByName("ROLE_USER");
            if (userRole == null) {
                userRole = roleRepo.save(new Role(null, "ROLE_USER"));
            }

            User admin = new User(null, "admin", encoder.encode("1234"), true, List.of(adminRole, userRole));
            User user = new User(null, "user", encoder.encode("1111"), true, List.of(userRole));

            userRepo.saveAll(List.of(admin, user));
        };
    }
}