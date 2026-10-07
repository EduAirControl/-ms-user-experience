package com.eduaircontrol.userexperience.shared.security;

import com.eduaircontrol.userexperience.shared.contract.UserIdentityPort;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Identidad del solicitante leida del token.
 */
@Component
@RequiredArgsConstructor
public class UserIdentityAdapter implements UserIdentityPort {

    private final JwtService jwtService;

    @Override
    public Optional<UUID> currentUserId() {
        return currentClaims().map(jwtService::optionalUserId).orElseGet(Optional::empty);
    }

    @Override
    public Optional<String> currentEmail() {
        return currentClaims()
                .map(claims -> claims.getSubject())
                .filter(email -> email != null && !email.isBlank());
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
}
