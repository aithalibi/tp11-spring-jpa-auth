package ma.fstg.security;

import ma.fstg.security.entities.Role;
import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.RoleRepository;
import ma.fstg.security.repositories.UserRepository;
import ma.fstg.security.services.CustomUserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class CustomUserDetailsServiceTest {

    @Autowired
    private CustomUserDetailsService service;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role admin = roleRepository.save(new Role(null, "ROLE_ADMIN"));
        Role user = roleRepository.save(new Role(null, "ROLE_USER"));
        userRepository.save(new User(null, "admin", passwordEncoder.encode("1234"), true, List.of(admin, user)));
        userRepository.save(new User(null, "user", passwordEncoder.encode("1111"), true, List.of(user)));
        userRepository.save(new User(null, "bloque", passwordEncoder.encode("0000"), false, List.of(user)));
    }

    @Test
    @DisplayName("L'utilisateur admin est charge avec ses deux roles")
    void loadsAdminWithBothRoles() {
        UserDetails details = service.loadUserByUsername("admin");

        assertThat(details.getUsername()).isEqualTo("admin");
        assertThat(details.getAuthorities())
                .extracting(Object::toString)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("L'utilisateur simple n'a que ROLE_USER")
    void loadsPlainUserWithSingleRole() {
        UserDetails details = service.loadUserByUsername("user");

        assertThat(details.getAuthorities())
                .extracting(Object::toString)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("Le mot de passe stocke est bien un hash BCrypt verifiable")
    void passwordIsBcryptHashed() {
        UserDetails details = service.loadUserByUsername("admin");

        assertThat(details.getPassword()).startsWith("$2");
        assertThat(passwordEncoder.matches("1234", details.getPassword())).isTrue();
        assertThat(passwordEncoder.matches("mauvais", details.getPassword())).isFalse();
    }

    @Test
    @DisplayName("Un compte desactive est charge mais marque non actif")
    void disabledAccountIsNotEnabled() {
        UserDetails details = service.loadUserByUsername("bloque");

        assertThat(details.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("Un utilisateur inconnu leve UsernameNotFoundException")
    void unknownUserThrows() {
        assertThatThrownBy(() -> service.loadUserByUsername("fantome"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("fantome");
    }
}