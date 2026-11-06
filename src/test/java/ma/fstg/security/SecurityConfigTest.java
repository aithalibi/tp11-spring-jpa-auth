package ma.fstg.security;

import ma.fstg.security.entities.Role;
import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.RoleRepository;
import ma.fstg.security.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

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
    }

    @Test
    @DisplayName("La page de connexion est accessible sans authentification")
    void loginPageIsPublic() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    @DisplayName("La page d'inscription est publique")
    void registerPageIsPublic() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    @DisplayName("Un anonyme est redirige vers /login sur une page protegee")
    void anonymousIsRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("Connexion reussie de user avec le mot de passe de la base")
    void userCanAuthenticate() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("1111"))
                .andExpect(authenticated().withUsername("user"))
                .andExpect(redirectedUrl("/home"));
    }

    @Test
    @DisplayName("Connexion reussie de admin avec le mot de passe de la base")
    void adminCanAuthenticate() throws Exception {
        mockMvc.perform(formLogin("/login").user("admin").password("1234"))
                .andExpect(authenticated().withUsername("admin"));
    }

    @Test
    @DisplayName("Un mot de passe errone est refuse")
    void wrongPasswordIsRejected() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("0000"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error=true"));
    }

    @Test
    @DisplayName("Un utilisateur absent de la base est refuse")
    void unknownUserIsRejected() throws Exception {
        mockMvc.perform(formLogin("/login").user("fantome").password("1111"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Le role USER accede a l'espace utilisateur")
    void userCanReachUserSpace() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("user-dashboard"));
    }

    @Test
    @DisplayName("Le role USER est refuse sur l'espace admin")
    void userCannotReachAdminSpace() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Le role ADMIN accede a l'espace admin et voit les comptes")
    void adminCanReachAdminSpace() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-dashboard"));
    }

    @Test
    @DisplayName("Le role ADMIN accede aussi a l'espace utilisateur")
    void adminCanReachUserSpace() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("L'inscription cree un compte actif avec ROLE_USER")
    void registerCreatesActiveUser() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("username", "hamza")
                        .param("password", "9999")
                        .param("confirmation", "9999"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));

        User cree = userRepository.findByUsername("hamza").orElseThrow();
        org.assertj.core.api.Assertions.assertThat(cree.isActive()).isTrue();
        org.assertj.core.api.Assertions.assertThat(cree.getRoles())
                .extracting(Role::getName)
                .containsExactly("ROLE_USER");
        org.assertj.core.api.Assertions.assertThat(cree.getPassword()).startsWith("$2");
    }

    @Test
    @DisplayName("Deux mots de passe differents sont rejetes a l'inscription")
    void registerRejectsPasswordMismatch() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("username", "sara")
                        .param("password", "9999")
                        .param("confirmation", "8888"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));

        org.assertj.core.api.Assertions.assertThat(userRepository.existsByUsername("sara")).isFalse();
    }

    @Test
    @DisplayName("Un nom deja utilise est rejete a l'inscription")
    void registerRejectsExistingUsername() throws Exception {
        mockMvc.perform(post("/register").with(csrf())
                        .param("username", "user")
                        .param("password", "9999")
                        .param("confirmation", "9999"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));

        org.assertj.core.api.Assertions.assertThat(userRepository.count()).isEqualTo(2);
    }

    @Test
    @DisplayName("La deconnexion redirige vers /login?logout=true")
    void logoutRedirectsWithMessage() throws Exception {
        mockMvc.perform(post("/logout").with(user("user").roles("USER")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout=true"));
    }
}