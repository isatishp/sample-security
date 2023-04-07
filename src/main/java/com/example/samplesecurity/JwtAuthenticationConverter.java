package com.example.samplesecurity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.json.JsonMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static java.time.Instant.now;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.of;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JsonMapper jsonmapper;

    private record Role(String name,
                        Set<Integer> markets,
                        Set<Character> division,
                        Set<String> subdivisions,
                        Set<String> rights,
                        Instant fromDate,
                        Instant toDate) {
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        var grantedAuthorities = new HashSet<GrantedAuthority>();
        if (jwt.hasClaim("roles")) {
            var jwtRoles = getRoles(jwt);

            var roles = jwtRoles.stream()
                    .map(Role::name)
                    .map(name -> "ROLE_" + name.replace(" ", "_").toUpperCase());

            var markets = jwtRoles.stream()
                    .map(Role::markets)
                    .flatMap(Collection::stream)
                    .map(market -> "MARKET_" + market);

            var divisions = jwtRoles.stream()
                    .map(Role::division)
                    .map(division -> "DIV_" + division);

            var subdivisions = jwtRoles.stream()
                    .map(Role::subdivisions)
                    .flatMap(Collection::stream)
                    .map(subdivision -> "SUBDIV_" + subdivision);

            var rights = jwtRoles.stream()
                    .map(Role::rights)
                    .flatMap(Collection::stream)
                    .map(right -> "RIGHT_" + right);

            of(roles, markets, divisions, subdivisions, rights)
                    .flatMap(identity())
                    .map(SimpleGrantedAuthority::new)
                    .forEach(grantedAuthorities::add);

        }
        return new JwtAuthenticationToken(jwt, grantedAuthorities);
    }

    private Set<Role> getRoles(Jwt jwt) {
        return jsonmapper.convertValue(jwt.getClaim("roles"), new TypeReference<Set<Role>>() {
                })
                .stream()
                .filter(role -> isBetween(role.fromDate, role.toDate))
                .collect(toSet());
    }

    private boolean isBetween(Instant fromDate, Instant toDate) {
        var now = now();
        return fromDate.isBefore(now) && toDate.isAfter(now);
    }
}
