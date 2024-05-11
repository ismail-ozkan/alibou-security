package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3tqPUqIhom4aNcQ7FxPoKZtTIi1g8IYS";

    private Claims extractAllClaims(String jwtToken) {
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .parseClaimsJws(jwtToken)
                .getBody();
    }
    public String extractUsername(String jwtToken) throws ParseException {
        return extractClaim(jwtToken,Claims::getSubject);// burda kaldık
        //https://www.youtube.com/watch?v=KxqlJblhzfI
        // 1:03:31
    }

    public  <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claimsSet = extractAllClaims(jwtToken);
        return claimsResolver.apply(claimsSet);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*60*24))
                .signWith(SignatureAlgorithm.HS256, getSignInKey())
                .compact();

//        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
//
//        // Adding custom claims
//        if (extraClaims != null && !extraClaims.isEmpty()) {
//            extraClaims.forEach(claimsBuilder::claim);
//        }
//
//        // Setting subject
//        claimsBuilder.subject(userDetails.getUsername());
//
//        // Setting issued at
//        claimsBuilder.issueTime(new Date(System.currentTimeMillis()));
//
//        // Setting expiration
//        claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + 1000 * 60 * 24));
//
//        JWTClaimsSet claimsSet = claimsBuilder.build();
//
//        // Create JWS header with HMAC SHA-256 algorithm
//        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
//
//        // Create the signed JWT object
//        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
//        try {
//            JWSSigner signer = new MACSigner(getSignInKey().toString()); // Anahtarın byte dizisini alın
//            signedJWT.sign(signer);
//        } catch (JOSEException e) {
//            // İmzalama işlemi başarısız olduğunda yapılacak işlemler
//            e.printStackTrace(); // veya loglama
//        }
//
//        // Apply the HMAC protection
////        JWSSigner signer = new MACSigner(getSignInKey().toString());
////        signedJWT.sign(signer);
//
//        // Serialize the signed JWT to a compact form
//        return signedJWT.serialize();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) throws ParseException {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) throws ParseException {
        return extractExpiation(token).before(new Date());
    }

    private Date extractExpiation(String token) throws ParseException {
        return extractClaim(token, Claims::getExpiration);
    }

//    private JWTClaimsSet extractAllClaims(String jwtToken) throws ParseException {
//        SignedJWT signedJWT = SignedJWT.parse(jwtToken);
//        System.out.println("jwtToken = " + jwtToken);
//        //        try {
////            JWSSigner signer = new MACSigner(getSignInKey().getEncoded()); // Anahtarın byte dizisini alın
////            signedJWT.verify(JWSVerifier);
////        } catch (JOSEException e) {
////            // İmzalama işlemi başarısız olduğunda yapılacak işlemler
////            e.printStackTrace(); // veya loglama
////        }
//        return signedJWT.getJWTClaimsSet();
//    }

    private Key getSignInKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
//        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes,"AES");
    }
}
