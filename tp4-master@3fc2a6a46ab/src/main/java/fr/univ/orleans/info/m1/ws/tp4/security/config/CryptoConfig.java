package fr.univ.orleans.info.m1.ws.tp4.security.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

@Configuration
public class CryptoConfig {
    private static final String SECRET_KEY = "MySuperSecretKeyForJWTsguguofterdfyulioluktydfyiuofdtrsdfuliguydsrtfuftrsesj";


    @Bean
    public JWK getJWK(){
        // Créer une clé secrète avec SecretKeySpec
        Key key = new SecretKeySpec(SECRET_KEY.getBytes(), "HMACSHA256");
        // Créer un objet OctetSequenceKey pour la clé secrète
        JWK jwk = new OctetSequenceKey.Builder(key.getEncoded())
                .algorithm(JWSAlgorithm.HS256)
                .build();
        return jwk;
    }
}
