package ghkwhd.security.security.service;

import ghkwhd.security.member.domain.PrincipalDetail;
import ghkwhd.security.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("--------------------------- UserDetailsServiceImpl ---------------------------");
        log.info("username = {}", username);

        return memberRepository.findByEmail(username)
                .map(member -> new PrincipalDetail(member, Collections.singleton(new SimpleGrantedAuthority(member.getRole().getValue()))))
                .orElseThrow(() -> new UsernameNotFoundException("등록되지 않은 사용자입니다"));
    }
}
