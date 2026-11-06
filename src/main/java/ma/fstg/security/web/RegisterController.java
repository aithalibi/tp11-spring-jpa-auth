package ma.fstg.security.web;

import ma.fstg.security.entities.Role;
import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.RoleRepository;
import ma.fstg.security.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * Inscription publique : cree un compte actif avec le role ROLE_USER.
 * Le mot de passe est hache en BCrypt avant persistance.
 */
@Controller
public class RegisterController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public RegisterController(UserRepository userRepository,
                              RoleRepository roleRepository,
                              BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String formulaire() {
        return "register";
    }

    @PostMapping("/register")
    public String inscrire(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam String confirmation,
                           Model model) {
        if (username == null || username.isBlank()) {
            return erreur(model, "Le nom d'utilisateur est obligatoire.");
        }
        if (password == null || password.length() < 4) {
            return erreur(model, "Le mot de passe doit contenir au moins 4 caracteres.");
        }
        if (!password.equals(confirmation)) {
            return erreur(model, "Les deux mots de passe ne correspondent pas.");
        }
        if (userRepository.existsByUsername(username)) {
            return erreur(model, "Ce nom d'utilisateur est deja utilise.");
        }

        Role roleUser = roleRepository.findByName("ROLE_USER");
        if (roleUser == null) {
            roleUser = roleRepository.save(new Role(null, "ROLE_USER"));
        }

        userRepository.save(new User(null, username, passwordEncoder.encode(password), true, List.of(roleUser)));
        model.addAttribute("cree", username);
        return "login";
    }

    private String erreur(Model model, String message) {
        model.addAttribute("erreur", message);
        return "register";
    }
}