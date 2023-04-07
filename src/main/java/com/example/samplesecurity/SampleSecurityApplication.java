package com.example.samplesecurity;

import com.fasterxml.jackson.databind.json.JsonMapper;
import lombok.SneakyThrows;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpMethod.GET;

@SpringBootApplication
@EnableWebSecurity
public class SampleSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleSecurityApplication.class, args);
    }

    @Bean
    @SneakyThrows
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter) {
        http.authorizeHttpRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
        return http.build();
    }

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring().mvcMatchers("/JWKS");
	}

    @Bean
    public JsonMapper jsonmapper() {
        return JsonMapper.builder()
				.findAndAddModules()
                .build();
    }

    @RestController
    @RequestMapping("/hi")
    class GreetingController {
        @GetMapping
        String hello() {
            return "Hello";
        }
    }

	@RestController
	@RequestMapping("/JWKS")
	class JWKSController {
		@GetMapping
		String jwks() {
			return """
				{
				  "keys": [
				    {
				      "alg": "RS512",
				      "e": "AQAB",
				      "iss": "http://tex-service.ddps-dev",
				      "kid": "aK1qnCv/uFDjtV8gwNy1+7IpUT3ZKN8g/cq+pbVngOA=",
				      "kty": "RSA",
				      "n": "0SyVu3aoAJcVP8V7J0S8FEKvXWV4cxQZF1UH1ViWpwhIXpm_Sz6KC3aGW06nMQev_-n57fygmaYFVwx6JXLROFY55nBDs6JcEj-khcBKPwE4udtTy5HnXJApzKQXGJhMcS5W1zOm2OJ0edqNLuXhqZl-S0EIwhC-8Y6-e9mel1_Fsck573BfZ8bhRLlkd6Gc8g7ZQr_Ao5xf0t0hqGDhzQ3hhLb4mq087pcTXGXbT78-yCu08eLtGfHuuFBv-cUBJNz7N0Arj0J_22W0IeA1n8c339odfZ56Y7An3dlL-SA6CW7S8xwvoH4j3Cz-WuqywyfJsXkhIIeBDwli_6xgGpa_RVqmb--FUd42pWeN-915cBlQmEMGonmG41067M1YqK5MOcZLnQqRPDHvESZb1oORw99NdI3w6t8ghKpiXtl7zB4AsvZC-4OpSK5NoNgAPSdC7Lg1KRf0lKFf68QcMe_PjJD90NC3qk81qfOLZWiSnOgQFsIT7z2ew1uX74VqlU5yP5gQ4gt6HuRgpUcYo3FqLuAN9c5SOvAtlMhOdUawLHRFKX97PgkdZ0pYZUc-TRIEk0g78dCit-RYCL2K6vHZ4JnCX9detLISk4eDWng00WT43yXoUbWtAbonnjtlTky1BbLu7lsQJWFWe6YI3FmI9RnKrsFXPC61MU900_c",
				      "use": "sig"
				    }
				  ]
				}
				""";
		}
	}
}
