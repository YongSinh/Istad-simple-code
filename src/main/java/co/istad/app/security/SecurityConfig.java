package co.istad.app.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RSAKey rsaKey;
    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(token -> token.disable());

        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/anonymous/**", "/api/v1/auth/**").permitAll();
            auth.requestMatchers(HttpMethod.GET, "/api/v1/books/**").hasAuthority("SCOPE_book:read");
            auth.requestMatchers(HttpMethod.POST, "/api/v1/books/**").hasAuthority("SCOPE_book:write");
            auth.requestMatchers(HttpMethod.PUT, "/api/v1/books/**").hasAuthority("SCOPE_book:update");
            auth.requestMatchers(HttpMethod.DELETE, "/api/v1/books/**").hasAuthority("SCOPE_book:delete");
            auth.anyRequest().authenticated();
        });

        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt((jwt) -> jwt.decoder(jwtDecoder()))
        );

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {

        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            return NimbusJwtDecoder
                    .withPublicKey(rsaKey.toRSAPublicKey()).build();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

}
