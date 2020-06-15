package com.newzen.security.config.auth;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class MyUserDetailsService implements UserDetailsService {


    @Resource
    private MyUserDetailsServiceMapper myUserDetailsServiceMapper;
    /**
     * Locates the user based on the username. In the actual implementation, the search
     * may possibly be case sensitive, or case insensitive depending on how the
     * implementation instance is configured. In this case, the <code>UserDetails</code>
     * object that comes back may have a username that is of a different case than what
     * was actually requested..
     *
     * @param username the username identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     *                                   GrantedAuthority
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 加载用户基础信息
        MyUserDetails myUserDetails = myUserDetailsServiceMapper.findByUserName(username);
        // 加载用户角色列表
        List<String> roleCodes = myUserDetailsServiceMapper.findRoleByUserName(username);
        // 通过用户角色列表加载用户资源
        List<String> authorites = myUserDetailsServiceMapper.findAuthorityByRole(roleCodes);
        // 角色是一个特殊的权限, 需要加前缀ROLE_
        roleCodes = roleCodes.stream().map(rc -> "ROLE_" + rc)
                .collect(Collectors.toList());

        authorites.addAll(roleCodes);

        myUserDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(
                String.join(",", authorites)
        ));

        return myUserDetails;
    }
}
