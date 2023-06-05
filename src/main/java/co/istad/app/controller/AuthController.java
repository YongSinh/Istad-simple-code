package co.istad.app.controller;

import co.istad.app.dto.AuthDto;
import co.istad.app.dto.LogInDto;
import co.istad.app.dto.RefreshTokenDto;
import co.istad.app.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public AuthDto login(@RequestBody LogInDto logInDto) {
        return authService.login(logInDto);
    }

    @PostMapping("/refresh")
    public AuthDto refresh(@RequestBody RefreshTokenDto refreshTokenDto) {
        return authService.refresh(refreshTokenDto);
    }
}
