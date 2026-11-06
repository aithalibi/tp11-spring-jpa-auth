package ma.fstg.security.web;

import ma.fstg.security.entities.User;
import ma.fstg.security.repositories.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class HomeController {

    private final UserRepository userRepository;

    public HomeController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        model.addAttribute("utilisateur", authentication.getName());
        model.addAttribute("autorites", authentication.getAuthorities());
        return "home";
    }

    @GetMapping("/user/dashboard")
    public String userDashboard(Authentication authentication, Model model) {
        model.addAttribute("utilisateur", authentication.getName());
        model.addAttribute("autorites", authentication.getAuthorities());
        return "user-dashboard";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard(Authentication authentication, Model model) {
        List<User> comptes = userRepository.findAll();
        model.addAttribute("utilisateur", authentication.getName());
        model.addAttribute("comptes", comptes);
        return "admin-dashboard";
    }
}