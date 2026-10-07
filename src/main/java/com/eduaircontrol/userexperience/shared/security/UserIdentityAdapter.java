package com.eduaircontrol.userexperience.shared.security;

import com.eduaircontrol.userexperience.shared.contract.UserIdentityPort;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Identidad del solicitante leida del JWT o de los headers del gateway.
 */
@Component
@RequiredArgsConstructor
public class UserIdentityAdapter implements UserIdentityPort {

    private final JwtService jwtService;

    @Override
    public Optional<UUID> currentUserId() {
        // 1. Intentar desde el JWT
        Optional<UUID> fromJwt = currentClaims().map(jwtService::optionalUserId).orElseGet(Optional::empty);
        if (fromJwt.isPresent()) {
            return fromJwt;
        }
        // 2. Intentar desde headers del gateway
        return fromGatewayHeader("X-User-Id");
    }

    @Override
    public Optional<String> currentEmail() {
        // 1. Intentar desde el JWT
        Optional<String> fromJwt = currentClaims()
                .map(claims -> claims.getSubject())
                .filter(email -> email != null && !email.isBlank());
        if (fromJwt.isPresent()) {
            return fromJwt;
        }
        // 2. Intentar desde headers del gateway
        return fromGatewayStringHeader("X-User-Email");
    }

    private Optional<io.jsonwebtoken.Claims> currentClaims() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getCredentials() instanceof String token)) {
            return Optional.empty();
        }
        try {
            return Optional.of(jwtService.parse(token));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private Optional<UUID> fromGatewayHeader(String headerName) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                    RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return Optional.empty();
            }
            String value = attrs.getRequest().getHeader(headerName);
            if (value == null || value.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(UUID.fromString(value));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<String> fromGatewayStringHeader(String headerName) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                    RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return Optional.empty();
            }
            String value = attrs.getRequest().getHeader(headerName);
            if (value == null || value.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(value);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
