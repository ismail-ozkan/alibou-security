package com.alibou.security.config;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3tqPUqIhom4aNcQ7FxPoKZtTIi1g8IYS";
    public String extractUsername(String jwtToken) throws ParseException {
        return extractClaim(jwtToken,JWTClaimsSet::getSubject);// burda kaldık
        //https://www.youtube.com/watch?v=KxqlJblhzfI
        // 1:03:31
    }

    public  <T> T extractClaim(String jwtToken, Function<JWTClaimsSet, T> claimsResolver) throws ParseException {
        final JWTClaimsSet claimsSet = extractAllClaims(jwtToken);
        return claimsResolver.apply(claimsSet);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();

        // Adding custom claims
        if (extraClaims != null && !extraClaims.isEmpty()) {
            extraClaims.forEach(claimsBuilder::claim);
        }

        // Setting subject
        claimsBuilder.subject(userDetails.getUsername());

        // Setting issued at
        claimsBuilder.issueTime(new Date(System.currentTimeMillis()));

        // Setting expiration
        claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + 1000 * 60 * 24));

        JWTClaimsSet claimsSet = claimsBuilder.build();

        // Create JWS header with HMAC SHA-256 algorithm
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).build();

        // Create the signed JWT object
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        try {
            JWSSigner signer = new MACSigner(getSignInKey().toString()); // Anahtarın byte dizisini alın
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            // İmzalama işlemi başarısız olduğunda yapılacak işlemler
            e.printStackTrace(); // veya loglama
        }

        // Apply the HMAC protection
//        JWSSigner signer = new MACSigner(getSignInKey().toString());
//        signedJWT.sign(signer);

        // Serialize the signed JWT to a compact form
        return signedJWT.serialize();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) throws ParseException {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) throws ParseException {
        return extractExpiation(token).before(new Date());
    }

    private Date extractExpiation(String token) throws ParseException {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    private JWTClaimsSet extractAllClaims(String jwtToken) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(jwtToken);
        System.out.println("jwtToken = " + jwtToken);
        //        try {
//            JWSSigner signer = new MACSigner(getSignInKey().getEncoded()); // Anahtarın byte dizisini alın
//            signedJWT.verify(JWSVerifier);
//        } catch (JOSEException e) {
//            // İmzalama işlemi başarısız olduğunda yapılacak işlemler
//            e.printStackTrace(); // veya loglama
//        }
        return signedJWT.getJWTClaimsSet();
    }

    private Key getSignInKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes,"AES");
    }
}
