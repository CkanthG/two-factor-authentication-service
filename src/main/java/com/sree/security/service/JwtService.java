package com.sree.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "fc5W+PIftBE/+YWe8QydVqe4K9Mx/knq9Svi3V0UuxO6KB+QWep/2UM5GT4Mwm/RO0o1gRZGbo9DPg3AAmgQGW1iBZJtoNTYwVjFdF++9/L7OFtCN8jmM50oTgdL97WsEMntkIc7A0GZ2hh/ed+qBALy9/GxZelV+CT7gHG5ZItHc3oq6FkqF5wLcIg/Z1eJgBPO79QVOpDZ9wdt3xA5KFM6bI989hIFTmcO1SqIpiQ6Ey3w74iWYk9CdaKYgK63sIt0fN/+BTNfaJIP0ZPhbWOEG5wuY0VoWmJb9YlCUQzEpTgfbWQoPaYAPUu0qL9+5FssQ4H4l9zCXmXT16QEUA==";

    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public Boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        final String userEmail = extractUsername(jwtToken);
        return (userEmail.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    public String generateToken(
            Map<String, Objects> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .subject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String jwtToken) {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
