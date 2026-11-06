package ma.fstg.security;

import ma.fstg.security.entities.Role;
import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.RoleRepository;
import ma.fstg.security.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
class RepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role admin = roleRepository.save(new Role(null, "ROLE_ADMIN"));
        Role user = roleRepository.save(new Role(null, "ROLE_USER"));
        userRepository.save(new User(null, "admin", "hash-admin", true, List.of(admin, user)));
        userRepository.save(new User(null, "user", "hash-user", true, List.of(user)));
    }

    @Test
    @DisplayName("findByUsername retourne l'utilisateur persiste")
    void findByUsernameReturnsUser() {
        Optional<User> trouve = userRepository.findByUsername("admin");

        assertThat(trouve).isPresent();
        assertThat(trouve.get().getRoles()).hasSize(2);
        assertThat(trouve.get().isActive()).isTrue();
    }

    @Test
    @DisplayName("findByUsername retourne vide pour un inconnu")
    void findByUsernameUnknownIsEmpty() {
        assertThat(userRepository.findByUsername("fantome")).isEmpty();
    }

    @Test
    @DisplayName("existsByUsername detecte un compte existant")
    void existsByUsername() {
        assertThat(userRepository.existsByUsername("user")).isTrue();
        assertThat(userRepository.existsByUsername("inconnu")).isFalse();
    }

    @Test
    @DisplayName("findByName retourne le role attendu")
    void findByNameReturnsRole() {
        Role role = roleRepository.findByName("ROLE_ADMIN");

        assertThat(role).isNotNull();
        assertThat(role.getName()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("findByName retourne null pour un role absent")
    void findByNameUnknownIsNull() {
        assertThat(roleRepository.findByName("ROLE_MANAGER")).isNull();
    }

    @Test
    @DisplayName("La table de jointure user_roles est bien alimentee")
    void rolesAreLinkedThroughJoinTable() {
        User admin = userRepository.findByUsername("admin").orElseThrow();

        assertThat(admin.getRoles())
                .extracting(Role::getName)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        assertThat(userRepository.count()).isEqualTo(2);
        assertThat(roleRepository.count()).isEqualTo(2);
    }
}