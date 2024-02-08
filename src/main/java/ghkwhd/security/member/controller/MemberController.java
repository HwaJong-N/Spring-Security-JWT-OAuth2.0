package ghkwhd.security.member.controller;

import ghkwhd.security.member.domain.Member;
import ghkwhd.security.member.domain.MemberDTO;
import ghkwhd.security.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/signUp")
    public Map<String, String> signUp(@RequestBody MemberDTO memberDTO) {
        log.info("--------------------------- MemberController ---------------------------");
        log.info("memberDTO = {}", memberDTO);
        Map<String, String> response = new HashMap<>();
        Optional<Member> byEmail = memberService.findByEmail(memberDTO.getEmail());
        if (byEmail.isPresent()) {
            response.put("error", "이미 존재하는 이메일입니다");
        } else {
            memberService.saveMember(memberDTO);
            response.put("success", "성공적으로 처리하였습니다");
        }
        return response;
    }

}
