package org.example.app.controller

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.security.core.context.SecurityContextHolder

/**
 * Controller for handling authentication-related requests.
 * This controller handles login, logout, and authentication result pages.
 */
@Controller
class AuthController {

    /**
     * Handles requests to the login page.
     * 
     * @param error Optional error parameter indicating a failed login attempt
     * @param logout Optional logout parameter indicating a successful logout
     * @param model The model to add attributes to
     * @return The name of the login view template
     */
    @GetMapping("/login")
    fun login(
        error: String?,
        logout: String?,
        model: Model
    ): String {
        if (error != null) {
            model.addAttribute("error", "Invalid username or password")
        }

        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully")
        }

        return "login"
    }

    /**
     * Handles requests to the success page after successful authentication.
     * 
     * @param model The model to add attributes to
     * @return The name of the success view template
     */
    @GetMapping("/success")
    fun success(model: Model): String {
        val authentication = SecurityContextHolder.getContext().authentication
        model.addAttribute("username", authentication.name)
        model.addAttribute("authorities", authentication.authorities)
        return "success"
    }

    /**
     * Handles requests to the home page.
     * Redirects to the success page.
     * 
     * @return A redirect to the success page
     */
    @GetMapping("/")
    fun home(): String {
        return "redirect:/success"
    }
}
