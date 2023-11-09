package com.khomsi.site_project.configuration;

import com.khomsi.site_project.entity.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .authorizeHttpRequests((request)->
                request.requestMatchers("/admin/**")
                    .hasAuthority(Role.ADMIN.getAuthority())
                    .requestMatchers("/js/**", "/css/**", "/**").permitAll().anyRequest().authenticated())
            .formLogin((formLogin)->
                formLogin.loginPage("/login")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/", true).permitAll())
            .logout((logout)->
                logout.logoutSuccessUrl("/")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logut")).permitAll())
            .exceptionHandling((exceptionHandling)->
                exceptionHandling.accessDeniedPage("/error403"));

        return httpSecurity.build();
    }

    /*~~(Migrate manually based on https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)~~>*/

    protected AuthenticationManager configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource)
                .passwordEncoder(passwordEncoder)
                .usersByUsernameQuery("select login, password, 'true' as enabled from user where login=?")
                .authoritiesByUsernameQuery("select login, role from user where login=?");

        return auth.build();
    }

}
