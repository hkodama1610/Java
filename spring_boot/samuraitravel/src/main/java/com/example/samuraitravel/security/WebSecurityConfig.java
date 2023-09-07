package com.example.samuraitravel.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests((requests) -> requests
			// 全てのユーザーにアクセスを許可するURL
			.requestMatchers("/css/**","/images/**","js/**","/strage/**","/").permitAll()
			// 管理者にのみアクセスを許可するURL
			.requestMatchers("/admin/**").hasRole("ADMIN")
			// 上記以外のURLはログインが必要（会員または管理者のどちらでもOK）
			.anyRequest().authenticated()
		)
		.formLogin((form) -> form
			.loginPage("/login") // ログインページのURL
			.loginProcessingUrl("/login") // ログインフォームの送信先URL
			.defaultSuccessUrl("/?loggedIn") // ログイン成功時のリダイレクト先URL
			.failureUrl("/login?error") // ログイン失敗時のリダイレクト先URL
			.permitAll()
		)
		.logout((logout) -> logout
			.logoutSuccessUrl("/?loggedOut")
			.permitAll()
		);
		
		return http.build();
	}
	
	@Bean
	// パスワードのハッシュアルゴリズムを設定する
	public PasswordEncoder passwordEncorder() {
		return new BCryptPasswordEncoder();
	}
}
