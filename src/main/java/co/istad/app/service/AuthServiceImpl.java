package co.istad.app.service;

import co.istad.app.dto.LogInDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JwtEncoder jwtEncoder;
    private final DaoAuthenticationProvider daoAuthenticationProvider;

    @Override
    public String login(LogInDto logInDto) {

        Authentication auth = new UsernamePasswordAuthenticationToken(logInDto.email(), logInDto.password());
        auth = daoAuthenticationProvider.authenticate(auth);

        Instant now = Instant.now();

        String scope = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !authority.contains("ROLE_"))
                .collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .issuer("client")
                .expiresAt(now.plus(1, ChronoUnit.SECONDS))
                .subject(auth.getName())
                .claim("scope", scope)
                .build();

        String accessToken = jwtEncoder.encode(
                JwtEncoderParameters.from(jwtClaimsSet)
        ).getTokenValue();

        return accessToken;
    }
}
