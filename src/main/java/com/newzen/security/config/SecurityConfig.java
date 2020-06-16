package com.newzen.security.config;

import com.newzen.security.config.auth.*;
import com.newzen.security.config.auth.imagecode.CaptchaCodeFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.Resource;
import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) //方法级别的权限控制，默认是关闭的
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    private MyAuthenticationFailHandler myAuthenticationFailHandler;

    @Resource
    private MyUserDetailsService myUserDetailsService;

    @Resource
    private DataSource dataSource;

    @Resource
    private MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    private CaptchaCodeFilter captchaCodeFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        // 简单的认证方式
//        http.httpBasic()
//                .and()
//                .authorizeRequests().anyRequest()
//                .authenticated();
//        // 静态配置
//        http.csrf().disable()
//                .formLogin()
//                .loginPage("/login.html")
//                .usernameParameter("uname")//默认是 username
//                .passwordParameter("pword")//默认是password 与前台from表单提交要一致
//                .loginProcessingUrl("/login")
//                //.defaultSuccessUrl("/index")
//                .successHandler(myAuthenticationSuccessHandler)
//                .failureHandler(myAuthenticationFailHandler)
//                    .and()
//                .authorizeRequests()
//                    .antMatchers("/login.html", "/login").permitAll()
//                    .antMatchers("/biz1", "/biz2")
//                .hasAnyAuthority("ROLE_user", "ROLE_admin")
////                .antMatchers("/syslog", "/sysuser")
////                .hasAnyRole("admin")
////                .antMatchers("/syslog").hasAuthority("sys:log")
////                .antMatchers("/sysuser").hasAuthority("sys:user")
//                    .antMatchers("/syslog").hasAuthority("/sys_log")
//                    .antMatchers("/sysuser").hasAuthority("/sys_user")
//                .anyRequest()
//                .authenticated()
//                .and().sessionManagement()
//                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                    .invalidSessionUrl("/login.html")
//                    .sessionFixation().migrateSession()
//                    .maximumSessions(1)// 一个用户最大允许登录
//                    .maxSessionsPreventsLogin(false) // 踢掉之前的登录,如果true,表示,登录后,不允许再次登录
//                    .expiredSessionStrategy(new MyExpiredSessionStrategy()); // session失效提醒

        // 动态加载数据库中的数据
        http.addFilterBefore(captchaCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/sigout")// 个性化退出登录配置,默认是logout
                // .logoutSuccessUrl("/login.html") //退出登录后个性化配置的页面, 默认到login.html
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler(myLogoutSuccessHandler)
                .and()
                .rememberMe()
                .rememberMeParameter("remember-me-new") //传递参数的名称 默认remember-me
                .rememberMeCookieName("remember-me-cookie") //cookie的名称, 默认remember-me
                .tokenValiditySeconds( 2 * 24 * 60 * 60) // token过期时间
                .tokenRepository(persistentTokenRepository()) //将token持久化到数据库
                .and()
                .csrf().disable()
                .formLogin()
                .loginPage("/login.html")
                .usernameParameter("uname")//默认是 username
                .passwordParameter("pword")//默认是password 与前台from表单提交要一致
                .loginProcessingUrl("/login")
                //.defaultSuccessUrl("/index")
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailHandler)
                    .and()
                .authorizeRequests()
                .antMatchers("/login.html", "/login", "/kaptcha").permitAll()
                .antMatchers("/index").authenticated()  //首页登录就可以访问
                .anyRequest().access("@rbacService.hasPermission(request, authentication)")
                    .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/login.html")
                .sessionFixation().migrateSession()
                .maximumSessions(1)// 一个用户最大允许登录
                .maxSessionsPreventsLogin(false) // 踢掉之前的登录,如果true,表示,登录后,不允许再次登录
                .expiredSessionStrategy(new MyExpiredSessionStrategy()); // session失效提醒

    }

    public void configure(AuthenticationManagerBuilder auth) throws  Exception {
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password(passwordEncoder().encode("123456"))
//                .roles("user")
//                    .and()
//                .withUser("admin")
//                .password(passwordEncoder().encode("123456"))
//                .authorities("sys:log", "sys:user")
//                //.roles("admin")
//                    .and()
//                .passwordEncoder(passwordEncoder());
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 不需要任何权限可以访问静态资源
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);

        return tokenRepository;
    }

}
