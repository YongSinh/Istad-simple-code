package co.istad.app.service;

import co.istad.app.dto.AuthDto;
import co.istad.app.dto.LogInDto;
import co.istad.app.dto.RefreshTokenDto;
import co.istad.app.entity.User;
import com.nimbusds.jwt.JWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JwtEncoder accessTokenJwtEncoder;

    private JwtEncoder refreshTokenJwtEncoder;

    @Autowired
    public void setRefreshTokenJwtEncoder(@Qualifier("refreshTokenJwtEncoder") JwtEncoder refreshTokenJwtEncoder) {
        this.refreshTokenJwtEncoder = refreshTokenJwtEncoder;
    }

    private final DaoAuthenticationProvider daoAuthenticationProvider;

    private final JwtAuthenticationProvider jwtAuthenticationProvider;

   /* @Autowired
    @Qualifier("jwtRefreshTokenAuthProvider")
    public void setJwtAuthenticationProvider(JwtAuthenticationProvider jwtAuthenticationProvider) {
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }*/

    @Override
    public AuthDto login(LogInDto logInDto) {

        Authentication auth = new UsernamePasswordAuthenticationToken(logInDto.email(), logInDto.password());
        auth = daoAuthenticationProvider.authenticate(auth);

        Instant now = Instant.now();

        String scope = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !authority.contains("ROLE_"))
                .collect(Collectors.joining(" "));

        JwtClaimsSet accessTokenJwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .issuer("client")
                .expiresAt(now.plus(1, ChronoUnit.SECONDS))
                .subject(auth.getName())
                .claim("scope", scope)
                .build();

        JwtClaimsSet refreshTokenJwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .issuer("client")
                .expiresAt(now.plus(1, ChronoUnit.DAYS))
                .subject(auth.getName())
                .claim("scope", scope)
                .build();

        String accessToken = accessTokenJwtEncoder.encode(
                JwtEncoderParameters.from(accessTokenJwtClaimsSet)
        ).getTokenValue();

        String refreshToken = refreshTokenJwtEncoder.encode(
                JwtEncoderParameters.from(refreshTokenJwtClaimsSet)
        ).getTokenValue();

        return new AuthDto(accessToken, refreshToken);
    }

    @Override
    public AuthDto refresh(RefreshTokenDto refreshTokenDto) {

        Instant now = Instant.now();

        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(refreshTokenDto.refreshToken());

        Authentication auth = jwtAuthenticationProvider.authenticate(token);

        auth.getAuthorities().forEach(System.out::println);
        System.out.println("Principal: " + auth.getPrincipal());;

        Jwt jwt = (Jwt) auth.getCredentials();
        System.out.println("Scope by key: " + jwt.getClaims().get("scope"));
        System.out.println("Scope 2: " + jwt.getClaimAsString("scope"));
        System.out.println("Scope 3: " + jwt.getClaims());


        JwtClaimsSet accessTokenJwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .issuer("client")
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject(auth.getName())
                .claim("scope", jwt.getClaimAsString("scope"))
                .build();

        String accessToken = accessTokenJwtEncoder.encode(
                JwtEncoderParameters.from(accessTokenJwtClaimsSet)
        ).getTokenValue();

        return new AuthDto(accessToken, refreshTokenDto.refreshToken());
    }
}
