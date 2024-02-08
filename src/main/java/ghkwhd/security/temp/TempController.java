package ghkwhd.security.temp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TempController {
    @GetMapping("/secure")
    public Map<String, String> secureMethod() {
        return Map.of("success", "filter 성공");
    }
}
