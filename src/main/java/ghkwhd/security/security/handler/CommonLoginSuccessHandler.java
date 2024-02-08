package ghkwhd.security.security.handler;

import com.google.gson.Gson;
import ghkwhd.security.jwt.utils.JwtConstants;
import ghkwhd.security.jwt.utils.JwtUtils;
import ghkwhd.security.member.domain.PrincipalDetail;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
public class CommonLoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("--------------------------- CommonLoginSuccessHandler ---------------------------");

        PrincipalDetail principal = (PrincipalDetail) authentication.getPrincipal();

        log.info("authentication.getPrincipal() = {}", principal);

        Map<String, Object> memberInfo = principal.getMemberInfo();
        memberInfo.put("accessToken", JwtUtils.generateToken(memberInfo, JwtConstants.ACCESS_EXP_TIME));
        memberInfo.put("refreshToken", JwtUtils.generateToken(memberInfo, JwtConstants.REFRESH_EXP_TIME));

        Gson gson = new Gson();
        String json = gson.toJson(memberInfo);

        response.setContentType("application/json; charset=UTF-8");

        PrintWriter writer = response.getWriter();
        writer.println(json);
        writer.flush();
    }
}
