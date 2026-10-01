package com.anomaly.platform.dto;
import java.time.OffsetDateTime; import java.util.*;
public record ErrorResponse(String code,String message,List<String> details,String requestId,OffsetDateTime timestamp) {}
