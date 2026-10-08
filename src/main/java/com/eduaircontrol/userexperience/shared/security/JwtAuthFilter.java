package com.eduaircontrol.userexperience.shared.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Autentica contra los headers del gateway (trust-gateway-headers, ADR-016) o,
 * en su defecto, contra el JWT compartido.
 *
 * <p>El orden importa y es el mismo que en ms-environment-monitoring: primero los
 * headers internos del gateway, despues el Bearer. Si se invirtiera, el Bearer
 * llegaria siempre (el gateway lo reenvia tal cual), fallaria al validarse como
 * HS256 lo que en realidad es un token RS256 de ms-security, y el {@code return}
 * se comeria la rama del gateway dejando la peticion sin autenticar.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        // 1. Headers del gateway (prioritario: el gateway ya valido el JWT y reenvia
        //    el Authorization original, que aqui no se puede verificar por firma).
        String gatewayUserId = request.getHeader("X-User-Id");
        String gatewayRole = request.getHeader("X-User-Role");
        if (gatewayUserId != null && !gatewayUserId.isBlank()) {
            String email = request.getHeader("X-User-Email");
            String role = (gatewayRole != null && !gatewayRole.isBlank()) ? gatewayRole : "USER";
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            email != null ? email : gatewayUserId,
                            "gateway",
                            List.of(new SimpleGrantedAuthority("ROLE_" + role)));
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
            return;
        }

        // 2. JWT Bearer, para llamadas directas al servicio.
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                String email = jwtService.extractEmail(token);
                String role = jwtService.extractRole(token);
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                email, token,
                                List.of(new SimpleGrantedAuthority("ROLE_" + role)));
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                log.debug("Token invalido: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
