package com.anomaly.platform.detection;

import com.anomaly.platform.entity.Event;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/*
 * ============================================================
 * SAFE PAYLOAD ACCESS
 * ============================================================
 *
 * `events.payload` is jsonb: every field is optional, any field can be the wrong
 * type, and a payload written by one producer may be missing a field another
 * producer always sends. A rule that reads it with a cast is a rule that crashes
 * the pipeline on a malformed event.
 *
 * Everything here returns Optional/empty rather than throwing, so "the field is
 * missing" and "the field is the wrong type" both land in the same place: the
 * rule simply does not match. A missing optional field can never fail an event.
 *
 * The field vocabulary below is the one this platform actually produces - see
 * the physical collector's normalizer.py, the Python simulator's
 * event_generator.py, the frontend simulator's builders, and the ML adapter's
 * api.py _canonical_event. Nothing here invents a field.
 */
public final class EventPayloads {

    private EventPayloads() {
    }

    /* ---------------- envelope-level event types this platform produces ---------------- */

    public static final String LOGIN = "LOGIN";
    public static final String LOGOUT = "LOGOUT";
    public static final String FILE_ACCESS = "FILE_ACCESS";
    public static final String API_ACCESS = "API_ACCESS";
    public static final String TRANSACTION = "TRANSACTION";
    public static final String PASSWORD_CHANGE = "PASSWORD_CHANGE";
    public static final String PROCESS_START = "PROCESS_START";
    public static final String NETWORK_CONNECTION = "NETWORK_CONNECTION";

    /*
     * The exact form DeterministicRuleService has always compared a
     * NETWORK_CONNECTION's processCreateTime against: a PROCESS_START's
     * occurredAt in UTC, truncated to whole seconds. Preserved verbatim - the
     * correlation contract has no time tolerance and must not gain one.
     */
    private static final DateTimeFormatter PROCESS_CREATE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public static Map<String, Object> payload(Event event) {
        Map<String, Object> p = event == null ? null : event.getPayload();
        return p == null ? Map.of() : p;
    }

    public static Optional<String> string(Event event, String key) {
        Object v = payload(event).get(key);
        if (v == null) {
            return Optional.empty();
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? Optional.empty() : Optional.of(s);
    }

    /** The first of `keys` that is present, for fields producers spell differently (resource / fileName). */
    public static Optional<String> firstString(Event event, String... keys) {
        for (String key : keys) {
            Optional<String> v = string(event, key);
            if (v.isPresent()) {
                return v;
            }
        }
        return Optional.empty();
    }

    public static Optional<Long> longValue(Event event, String key) {
        Object v = payload(event).get(key);
        if (v instanceof Number n) {
            return Optional.of(n.longValue());
        }
        // A jsonb round trip can hand back a numeric string; a non-numeric string is simply absent.
        if (v instanceof String s) {
            try {
                return Optional.of(Long.parseLong(s.trim()));
            } catch (NumberFormatException ignored) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public static Optional<Double> doubleValue(Event event, String key) {
        Object v = payload(event).get(key);
        if (v instanceof Number n) {
            double d = n.doubleValue();
            return Double.isFinite(d) ? Optional.of(d) : Optional.empty();
        }
        if (v instanceof String s) {
            try {
                double d = Double.parseDouble(s.trim());
                return Double.isFinite(d) ? Optional.of(d) : Optional.empty();
            } catch (NumberFormatException ignored) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /* ---------------- authentication ---------------- */

    /**
     * A reported authentication FAILURE. Strictly `loginSuccess == false`, the
     * same test AUTH_BURST has always used: a missing result is never read as a
     * failure, and never as a success either.
     */
    public static boolean isAuthFailure(Event event) {
        return Boolean.FALSE.equals(payload(event).get("loginSuccess"));
    }

    /** A reported authentication SUCCESS. Strictly `loginSuccess == true`. */
    public static boolean isAuthSuccess(Event event) {
        return Boolean.TRUE.equals(payload(event).get("loginSuccess"));
    }

    /** Whether the payload states an authentication result at all. */
    public static boolean hasAuthResult(Event event) {
        return payload(event).get("loginSuccess") instanceof Boolean;
    }

    /**
     * The source address the authentication came from. This is the only
     * source-side identity the LOGIN schema carries, so it is what the
     * source-correlated rules (PASSWORD_SPRAY, ACCOUNT_ENUMERATION) key on.
     */
    public static Optional<String> sourceIp(Event event) {
        return firstString(event, "ip", "sourceIp");
    }

    /** The account named in the payload, when the producer supplies one (the collector does). */
    public static Optional<String> username(Event event) {
        return string(event, "username");
    }

    /** `City|lat|lon`, as produced by the simulators. The physical collector performs no geo lookup. */
    public static Optional<String> location(Event event) {
        return firstString(event, "location", "geoLocation");
    }

    public static Optional<String> authMethod(Event event) {
        return firstString(event, "authMethod", "auth_method");
    }

    public static Optional<String> deviceFingerprint(Event event) {
        return firstString(event, "deviceFingerprint", "device_fingerprint");
    }

    /* ---------------- endpoint and file activity ---------------- */

    public static Optional<Long> pid(Event event) {
        return longValue(event, "pid");
    }

    public static Optional<String> processName(Event event) {
        return string(event, "processName");
    }

    public static Optional<String> executablePath(Event event) {
        return string(event, "executablePath");
    }

    public static Optional<String> processCreateTime(Event event) {
        return string(event, "processCreateTime");
    }

    public static Optional<String> resource(Event event) {
        return firstString(event, "resource", "fileName", "endpoint");
    }

    public static Optional<String> commandSequence(Event event) {
        return firstString(event, "commandSequence", "command_sequence");
    }

    /*
     * Tokens that mean "this activity ran with elevated privilege" in the only
     * field this platform has that can say so: FILE_ACCESS.commandSequence, and
     * a PROCESS_START's own name/path. There is NO PRIVILEGE_CHANGE event type
     * and no privilege field in the schema - see PrivilegeEscalationChainRule
     * for what that means for R007.
     */
    private static final List<String> PRIVILEGE_TOKENS =
            List.of("sudo", "su", "runas", "doas", "pkexec", "setuid", "administrator");

    /** Whether a FILE_ACCESS command sequence names a privilege-elevation command. */
    public static boolean hasPrivilegedCommand(Event event) {
        return commandSequence(event)
                .map(s -> s.toLowerCase())
                .map(s -> PRIVILEGE_TOKENS.stream().anyMatch(token -> containsToken(s, token)))
                .orElse(false);
    }

    /** Whether a PROCESS_START is itself a privilege-elevation binary. */
    public static boolean isPrivilegedProcess(Event event) {
        String name = processName(event).orElse("") + " " + executablePath(event).orElse("");
        String lower = name.toLowerCase();
        return PRIVILEGE_TOKENS.stream().anyMatch(token -> containsToken(lower, token));
    }

    /** Word-boundary match, so "sudo" does not fire on "pseudonym" or "sudoku". */
    private static boolean containsToken(String haystack, String token) {
        int from = 0;
        while (true) {
            int at = haystack.indexOf(token, from);
            if (at < 0) {
                return false;
            }
            boolean leftOk = at == 0 || !Character.isLetterOrDigit(haystack.charAt(at - 1));
            int end = at + token.length();
            boolean rightOk = end >= haystack.length() || !Character.isLetterOrDigit(haystack.charAt(end));
            if (leftOk && rightOk) {
                return true;
            }
            from = at + 1;
        }
    }

    /* ---------------- network ---------------- */

    public static Optional<String> remoteAddress(Event event) {
        return string(event, "remoteAddress");
    }

    public static Optional<Long> remotePort(Event event) {
        return longValue(event, "remotePort");
    }

    /**
     * Loopback, exactly as DeterministicRuleService has always defined it.
     * Preserved verbatim: widening this would change which NETWORK_CONNECTION
     * events R002 fires on.
     */
    public static boolean isLoopback(String address) {
        if (address == null) {
            return false;
        }
        return address.startsWith("127.") || "::1".equals(address) || "localhost".equalsIgnoreCase(address);
    }

    /**
     * "External" in this codebase means NON-LOOPBACK, which is what the OS
     * connection table can actually tell us - the payload carries no routing or
     * interface information to distinguish a LAN peer from the internet. Rules
     * that would be noisy under that definition (NETWORK_CONNECTION_BURST) use a
     * distinct-destination threshold rather than pretending to classify ranges.
     */
    public static boolean isExternalDestination(Event event) {
        return remoteAddress(event).filter(a -> !isLoopback(a)).isPresent();
    }

    /**
     * The identity of the process a NETWORK_CONNECTION belongs to, as a single
     * string: `pid@processCreateTime`. Empty when either field is missing.
     *
     * Defined once and used by every rule that suppresses per process (R002, R008)
     * so the two can never drift apart on what "the same process" means - and so
     * the engine can rebuild a stored alert's key from its own triggering event
     * and compare like with like.
     */
    public static Optional<String> processIdentity(Event networkConnection) {
        Optional<Long> pid = pid(networkConnection);
        Optional<String> createTime = processCreateTime(networkConnection);
        if (pid.isEmpty() || createTime.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(pid.get() + "@" + createTime.get());
    }

    /** `occurredAt` in the exact string form a NETWORK_CONNECTION's processCreateTime must equal. */
    public static String formatProcessCreateTime(Event processStart) {
        return processStart.getOccurredAt()
                .withOffsetSameInstant(ZoneOffset.UTC)
                .format(PROCESS_CREATE_TIME);
    }

    /**
     * Whether a NETWORK_CONNECTION and a PROCESS_START describe the SAME process:
     * the same numeric pid AND a processCreateTime equal, character for
     * character, to that PROCESS_START's occurredAt truncated to the second.
     * No tolerance - a reused pid is a different process.
     */
    public static boolean sameProcess(Event networkConnection, Event processStart) {
        Optional<Long> connPid = pid(networkConnection);
        Optional<Long> startPid = pid(processStart);
        if (connPid.isEmpty() || startPid.isEmpty() || !connPid.get().equals(startPid.get())) {
            return false;
        }
        return processCreateTime(networkConnection)
                .map(t -> t.equals(formatProcessCreateTime(processStart)))
                .orElse(false);
    }
}
