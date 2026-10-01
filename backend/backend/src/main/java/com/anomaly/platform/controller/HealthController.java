package com.anomaly.platform.controller;
import org.springframework.web.bind.annotation.*; import java.time.OffsetDateTime; import java.util.Map;
@RestController @RequestMapping("/api/v1/health")
public class HealthController {
    @GetMapping public Map<String,Object> health(){
        return Map.of("status","UP","timestamp",OffsetDateTime.now());
    }
}
