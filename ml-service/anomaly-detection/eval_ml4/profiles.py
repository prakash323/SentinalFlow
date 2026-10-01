"""Generator profiles for ML-4. Each profile is a full parameter set; P0 replicates the behavioural constants of the production generator
(src/generate.py) and is the control. P1-P4 change the constants the production generator hard-codes.

Axes varied (requirement 2): attacker timing (windows, hours, campaigns), source/destination patterns (source IP kinds, victim roles),
entity distributions (counts, type mix, roles, shifts, time zones), IP characteristics (private / public-dynamic / mixed, NAT sharing,
residential ranges), authentication behaviour (normal failure rate, success ratios inside attacks), command/resource behaviour (vocabularies,
sensitive sets, privileged commands, malicious chains), city/location behaviour (regions, travel, near-miss flights, VPN exits), device
identity behaviour (spoof variants, firmware refresh, cloned fingerprints), attack intensity and duration.
"""
from __future__ import annotations

import copy

import config as C

CITY = dict(C.CITIES)
CITY.update({
    "Berlin": (52.52, 13.41), "Paris": (48.86, 2.35), "Madrid": (40.42, -3.70), "Rome": (41.90, 12.50), "Warsaw": (52.23, 21.01),
    "Chicago": (41.88, -87.63), "Dallas": (32.78, -96.80), "Seattle": (47.61, -122.33), "Boston": (42.36, -71.06), "Atlanta": (33.75, -84.39),
    "Denver": (39.74, -104.99), "Tokyo": (35.68, 139.69), "Seoul": (37.57, 126.98), "Sydney": (-33.87, 151.21), "Dubai": (25.20, 55.27),
    "Istanbul": (41.01, 28.98), "Toronto": (43.65, -79.38), "Mexico City": (19.43, -99.13), "Jakarta": (-6.21, 106.85), "Cairo": (30.04, 31.24),
})

IN_HOME = list(C.HOME_CITIES)
EU_HOME = ["Frankfurt", "Berlin", "Paris", "Amsterdam", "Madrid", "Rome"]
US_HOME = ["Chicago", "Dallas", "Boston", "Atlanta", "Denver", "Seattle"]
MIX_HOME = ["Frankfurt", "Chicago", "Singapore", "Bengaluru", "London", "Dallas"]
WORLD = ["Lagos", "Moscow", "Sao Paulo", "Shenzhen", "Dubai", "Istanbul", "Cairo", "Jakarta", "Mexico City", "Sydney", "Tokyo", "Seoul", "Toronto",
         "New York", "Phoenix", "London", "Singapore", "Frankfurt", "Amsterdam"]

DEFAULTS = {
    "version": "1.0", "name": "P0", "description": "replica of the production generator's behavioural constants",
    "n_users": 140, "n_service": 40, "n_devices": 20, "start_offset_days": 0,
    "roles": list(C.ROLES), "priv_roles": ["admin", "ops", "engineer"],
    "home_cities": IN_HOME, "foreign_cities": [c for c in C.CITIES if c not in IN_HOME],
    "resources": copy.deepcopy(C.RESOURCES), "sensitive": sorted(C.SENSITIVE),
    "commands": {"vocab": list(C.COMMANDS), "priv": ["sudo", "exec", "delete", "download"], "malicious": ["list", "sudo", "read", "read", "download"],
                 "start": {"admin": "sudo", "ops": "read", "engineer": "list"}, "default_start": "read", "original_chains": True},
    "hours": {"user_mean": (10.0, 1.6), "user_sd": (1.2, 2.6), "tz_offsets": [0.0], "shifts": None},
    "events_per_day": {"user": (18, 55), "service": (120, 400), "edge": (200, 500)},
    "weekend": {"user": (0.02, 0.25), "service": (0.85, 1.0), "edge": (1.0, 1.0)},
    "periodic_devices": False,
    "ip": {"mode": "private_pool", "pool_size": {"user": 3, "service": 2, "edge": 1}, "nat_share": 0.0, "n_shared": 6, "rotate_daily": False,
           "private_bases": ["10"], "public_isp": ["73.12", "98.204", "24.6", "68.45", "174.55", "108.20", "71.199", "50.35", "76.101", "99.66"],
           "travel_ip": "private192"},
    "auth": {"fail_rate": {"user": 0.02, "service": 0.02, "edge": 0.02}, "alt_method_p": 0.0,
             "user_methods": ["password", "password", "biometric"], "service_methods": ["token", "certificate"], "edge_methods": ["certificate"]},
    "confounder": {"rate": 0.06, "travel_p": 0.35, "atypical_res_p": 0.3},
    "device": {"user_os": list(C.OS_POOL[:6]), "service_os": ["Ubuntu 22.04", "RHEL 9.3"], "edge_os": ["Yocto 4.0", "FreeRTOS 10.5"],
               "user_proto": ["TLS1.3"], "service_proto": ["TLS1.2"], "edge_proto": ["MQTT3.1.1", "OPC-UA"], "os_pool_all": list(C.OS_POOL),
               "proto_pool_all": list(C.PROTOCOLS)},
    "attacks": {
        "brute_force": {"n": 4, "events": (30, 200), "gap_s": (1, 12), "src": "public", "city": "foreign", "fail_share": (1.0, 1.0),
                        "success_end_p": 0.4, "window": (0.70, 1.0), "victims": "any"},
        "credential_stuffing": {"n": 3, "victims": (25, 70), "n_ips": (2, 4), "src": "public", "city": "foreign", "spread_s": (0, 40), "tries": (1, 4),
                                "success_p": 0.03, "window": (0.70, 1.0), "victim_types": "any"},
        "impossible_travel": {"n": 10, "gap_h": (0.4, 1.6), "min_km": 6000, "src2": "public", "near_miss": 0.5, "window": (0.70, 1.0), "hops": 1,
                              "victim_types": "any"},
        "lateral_movement": {"n": 4, "events": (15, 45), "gap_min": (1.5, 6), "hours": (1, 5), "foreign": "all", "cmd": "malicious", "ip": "own",
                             "window": (0.70, 1.0), "victim_types": "any"},
        "device_spoofing": {"n": 6, "events": (6, 25), "gap_min": (2, 15), "variants": {"full_swap": 1.0}, "ip": "own", "clone_ip_new_p": 0.0,
                            "window": (0.70, 1.0), "victim_types": "edge_service"},
        "low_slow_exfil": {"n": 4, "span_days": (6, 14), "per_day": (1, 4), "hours": [1, 2, 3, 22, 23], "res": "sensitive", "ip": "own",
                           "window": (0.68, 0.95)},
    },
    "benign_drift": {"n": 3, "kind": "resources", "start_frac": 0.55, "days": 14},
    "drift": None,
}

PROFILES = {
    "P0": {},
    "P1": {
        "name": "P1", "description": "stealth-internal enterprise: attackers operate from internal hosts, mostly succeed at authentication, business hours",
        "n_users": 100, "n_service": 30, "n_devices": 10,
        "roles": ["dev", "finance", "hr", "sysadmin", "support"], "priv_roles": ["sysadmin", "dev"],
        "home_cities": EU_HOME, "foreign_cities": WORLD,
        "resources": {
            "dev": ["/git/core", "/git/api", "/ci/pipeline", "/k8s/dev", "/logs/app", "/db/dev", "/artifact/repo", "/secrets/dev"],
            "finance": ["/erp/ledger", "/erp/ap", "/erp/ar", "/reports/quarter", "/db/finance", "/payroll/run", "/bank/transfers"],
            "hr": ["/hris/profiles", "/hris/payroll", "/docs/policy", "/ats/candidates", "/benefits/portal"],
            "sysadmin": ["/ad/users", "/vpn/config", "/backup/nightly", "/patch/console", "/dhcp/leases", "/dns/zones", "/db/prod"],
            "support": ["/crm/tickets", "/crm/accounts", "/kb/articles", "/chat/queue", "/remote/assist"],
            "service_account": ["/api/v2/ingest", "/api/v2/sync", "/queue/work", "/db/replica", "/metrics/push", "/healthz"],
            "edge_device": ["sensor/temp", "sensor/door", "badge/reader", "heartbeat", "firmware/check", "telemetry/upload"]},
        "sensitive": ["/ad/users", "/db/prod", "/secrets/dev", "/payroll/run", "/bank/transfers", "/hris/payroll", "/db/finance"],
        "commands": {"vocab": ["list", "read", "write", "exec", "sudo", "download", "delete"], "priv": ["sudo", "exec", "delete", "download"],
                     "malicious": ["list", "read", "download", "read", "download"], "start": {"sysadmin": "sudo", "dev": "list"}, "default_start": "read",
                     "original_chains": True},
        "hours": {"user_mean": (13.0, 1.8), "user_sd": (1.5, 3.0), "tz_offsets": [0.0], "shifts": None},
        "events_per_day": {"user": (15, 45), "service": (100, 320), "edge": (150, 400)},
        "ip": {"mode": "private_pool", "pool_size": {"user": 2, "service": 2, "edge": 1}, "nat_share": 0.30, "n_shared": 6, "rotate_daily": False,
               "private_bases": ["10", "172.16"], "public_isp": ["81.12", "82.45", "90.146"], "travel_ip": "private192"},
        "auth": {"fail_rate": {"user": 0.015, "service": 0.01, "edge": 0.01}, "alt_method_p": 0.03, "user_methods": ["password", "token"],
                 "service_methods": ["token", "certificate"], "edge_methods": ["certificate"]},
        "confounder": {"rate": 0.03, "travel_p": 0.30, "atypical_res_p": 0.25},
        "device": {"user_os": ["Windows 11.0.22631", "Windows 10.0.19045", "macOS 14.4", "Ubuntu 24.04"], "service_os": ["RHEL 9.3", "Ubuntu 22.04"],
                   "edge_os": ["Yocto 4.0", "FreeRTOS 10.5"], "user_proto": ["TLS1.3", "TLS1.2"], "service_proto": ["TLS1.2"],
                   "edge_proto": ["MQTT3.1.1"], "os_pool_all": list(C.OS_POOL), "proto_pool_all": list(C.PROTOCOLS)},
        "attacks": {
            "brute_force": {"n": 4, "events": (25, 60), "gap_s": (20, 120), "src": "private_internal", "city": "home", "fail_share": (0.55, 0.8),
                            "success_end_p": 0.7, "window": (0.42, 0.97), "victims": "user", "hour_range": (9, 18)},
            "credential_stuffing": {"n": 3, "victims": (8, 20), "n_ips": (1, 2), "src": "private_internal", "city": "home", "spread_s": (600, 3600),
                                    "tries": (1, 2), "success_p": 0.08, "window": (0.42, 0.97), "victim_types": "user", "hour_range": (9, 18)},
            "impossible_travel": {"n": 10, "gap_h": (0.8, 1.9), "min_km": 2500, "max_km": 5500, "src2": "private_internal", "near_miss": 0.8,
                                  "window": (0.42, 0.97), "hops": 1, "victim_types": "user", "hour_range": (9, 19)},
            "lateral_movement": {"n": 4, "events": (12, 30), "gap_min": (8, 40), "hours": (9, 17), "foreign": "peer", "cmd": "normal", "ip": "own",
                                 "window": (0.42, 0.97), "victim_types": "user"},
            "device_spoofing": {"n": 6, "events": (8, 30), "gap_min": (5, 30), "variants": {"partial_mac": 0.45, "full_swap": 0.25, "protocol_only": 0.30},
                                "ip": "own", "clone_ip_new_p": 0.0, "window": (0.42, 0.97), "victim_types": "edge_service", "hour_range": (8, 18)},
            "low_slow_exfil": {"n": 4, "span_days": (10, 20), "per_day": (1, 2), "hours": [9, 10, 11, 14, 15, 16], "res": "mixed", "ip": "own",
                               "window": (0.42, 0.70)},
        },
        "benign_drift": {"n": 3, "kind": "resources", "start_frac": 0.50, "days": 14},
    },
    "P2": {
        "name": "P2", "description": "remote-workforce SaaS: normal users on dynamic public IPs across time zones, noisy authentication, frequent travel",
        "n_users": 220, "n_service": 15, "n_devices": 5,
        "roles": ["sales", "marketing", "product", "eng", "exec"], "priv_roles": ["eng", "exec"],
        "home_cities": US_HOME, "foreign_cities": WORLD,
        "resources": {
            "sales": ["/crm/leads", "/crm/opps", "/crm/accounts", "/crm/export", "/wiki/spaces", "/mail/shared"],
            "marketing": ["/mkt/campaigns", "/mkt/analytics", "/cms/pages", "/cms/assets", "/wiki/spaces", "/social/queue"],
            "product": ["/prod/roadmap", "/prod/specs", "/wiki/spaces", "/analytics/funnel", "/design/files", "/feedback/inbox"],
            "eng": ["/repo/web", "/repo/mobile", "/ci/main", "/cloud/console", "/cloud/billing", "/logs/prod", "/wiki/spaces", "/feature/flags"],
            "exec": ["/exec/board", "/exec/finance-dash", "/hr/comp-bands", "/crm/opps", "/prod/roadmap", "/cloud/billing"],
            "service_account": ["/svc/webhook", "/svc/sync", "/svc/queue", "/svc/billing", "/svc/health"],
            "edge_device": ["kiosk/checkin", "kiosk/print", "heartbeat", "telemetry/upload"]},
        "sensitive": ["/exec/board", "/exec/finance-dash", "/hr/comp-bands", "/cloud/billing", "/crm/export"],
        "commands": {"vocab": ["view", "edit", "share", "export", "invite", "admin", "comment"], "priv": ["export", "share", "admin"],
                     "malicious": ["view", "export", "export", "share", "admin"], "start": {"eng": "view", "exec": "view"}, "default_start": "view",
                     "original_chains": False},
        "hours": {"user_mean": (10.0, 1.8), "user_sd": (1.4, 3.0), "tz_offsets": [-8.0, -5.0, 0.0, 1.0, 5.5], "shifts": None},
        "events_per_day": {"user": (14, 40), "service": (100, 260), "edge": (60, 150)},
        "weekend": {"user": (0.10, 0.45), "service": (0.9, 1.0), "edge": (1.0, 1.0)},
        "ip": {"mode": "public_dynamic", "pool_size": {"user": 5, "service": 2, "edge": 1}, "nat_share": 0.0, "n_shared": 4, "rotate_daily": True,
               "private_bases": ["10"], "public_isp": ["73.12", "98.204", "24.6", "68.45", "174.55", "108.20", "71.199", "50.35", "76.101", "99.66",
                                                       "67.180", "96.44", "72.21", "184.96", "47.144"], "travel_ip": "public"},
        "auth": {"fail_rate": {"user": 0.06, "service": 0.02, "edge": 0.01}, "alt_method_p": 0.10, "user_methods": ["password", "token", "biometric"],
                 "service_methods": ["token"], "edge_methods": ["token"]},
        "confounder": {"rate": 0.12, "travel_p": 0.50, "atypical_res_p": 0.35},
        "device": {"user_os": ["macOS 14.4", "Windows 11.0.22631", "Windows 10.0.19045", "Ubuntu 24.04"], "service_os": ["Ubuntu 22.04"],
                   "edge_os": ["Ubuntu 24.04", "Yocto 4.0"], "user_proto": ["HTTPS", "TLS1.3"], "service_proto": ["HTTPS"], "edge_proto": ["HTTPS"],
                   "os_pool_all": list(C.OS_POOL), "proto_pool_all": list(C.PROTOCOLS)},
        "attacks": {
            "brute_force": {"n": 4, "events": (40, 300), "gap_s": (3, 40), "src": "residential", "city": "foreign", "fail_share": (0.70, 0.92),
                            "success_end_p": 0.5, "window": (0.40, 1.0), "victims": "user"},
            "credential_stuffing": {"n": 3, "victims": (30, 90), "n_ips": (15, 40), "src": "residential", "city": "foreign", "spread_s": (5, 60),
                                    "tries": (1, 3), "success_p": 0.05, "window": (0.40, 1.0), "victim_types": "user"},
            "impossible_travel": {"n": 10, "gap_h": (0.5, 1.5), "min_km": 3500, "src2": "residential", "near_miss": 1.2, "window": (0.40, 1.0), "hops": 1,
                                  "victim_types": "user"},
            "lateral_movement": {"n": 4, "events": (15, 50), "gap_min": (2, 15), "hours": (20, 21, 22, 23, 0, 1), "foreign": "all", "cmd": "mixed",
                                 "ip": "own", "window": (0.40, 1.0), "victim_types": "user"},
            "device_spoofing": {"n": 5, "events": (6, 25), "gap_min": (2, 15), "variants": {"clone": 0.4, "partial_mac": 0.3, "partial_os": 0.3},
                                "ip": "own", "clone_ip_new_p": 0.7, "window": (0.40, 1.0), "victim_types": "any"},
            "low_slow_exfil": {"n": 4, "span_days": (8, 20), "per_day": (1, 3), "hours": [20, 21, 22, 23, 0, 1, 2, 3], "res": "sensitive", "ip": "own",
                               "window": (0.40, 0.75)},
        },
        "benign_drift": {"n": 4, "kind": "resources", "start_frac": 0.50, "days": 14},
    },
    "P3": {
        "name": "P3", "description": "OT/IoT plant: device-heavy, periodic heartbeat cadence, shifts, NAT gateways, different vocabulary, firmware refresh",
        "n_users": 30, "n_service": 70, "n_devices": 100, "start_offset_days": 2,
        "roles": ["operator", "maintenance", "engineer_ot", "supervisor"], "priv_roles": ["maintenance", "engineer_ot"],
        "home_cities": ["Chicago", "Dallas", "Atlanta", "Denver"], "foreign_cities": WORLD,
        "resources": {
            "operator": ["/hmi/panel1", "/hmi/panel3", "/opc/line1", "/opc/line2", "/alarms/ack", "/historian/tags"],
            "maintenance": ["/maint/tickets", "/plc/prog", "/plc/firmware", "/opc/line1", "/opc/boiler", "/alarms/ack", "/safety/interlock"],
            "engineer_ot": ["/plc/prog", "/opc/line1", "/opc/line2", "/opc/boiler", "/historian/tags", "/historian/export", "/plc/firmware"],
            "supervisor": ["/reports/shift", "/historian/tags", "/alarms/ack", "/maint/tickets", "/hmi/panel1"],
            "service_account": ["/api/telemetry", "/api/batch", "/mq/consume", "/db/historian", "/health"],
            "edge_device": ["sensor/temp", "sensor/vibration", "actuator/pump", "actuator/valve", "heartbeat", "fw/check", "telemetry/upload"]},
        "sensitive": ["/plc/prog", "/plc/firmware", "/safety/interlock", "/historian/export"],
        "commands": {"vocab": ["read_tag", "write_tag", "ack", "start", "stop", "upload_fw", "download_cfg"], "priv": ["write_tag", "stop", "upload_fw", "download_cfg"],
                     "malicious": ["read_tag", "download_cfg", "write_tag", "stop", "upload_fw"], "start": {"maintenance": "read_tag"}, "default_start": "read_tag",
                     "original_chains": False},
        "hours": {"user_mean": (10.0, 1.6), "user_sd": (1.5, 2.2), "tz_offsets": [0.0], "shifts": [6.0, 14.0, 22.0]},
        "events_per_day": {"user": (25, 60), "service": (80, 240), "edge": (100, 300)},
        "weekend": {"user": (0.6, 1.0), "service": (0.95, 1.0), "edge": (1.0, 1.0)},
        "periodic_devices": True,
        "ip": {"mode": "private_pool", "pool_size": {"user": 1, "service": 1, "edge": 1}, "nat_share": 0.65, "n_shared": 8, "rotate_daily": False,
               "private_bases": ["172.16", "192.168"], "public_isp": ["66.10"], "travel_ip": "private192"},
        "auth": {"fail_rate": {"user": 0.03, "service": 0.005, "edge": 0.005}, "alt_method_p": 0.0, "user_methods": ["password", "biometric"],
                 "service_methods": ["certificate", "token"], "edge_methods": ["certificate"]},
        "confounder": {"rate": 0.02, "travel_p": 0.0, "atypical_res_p": 0.5},
        "device": {"user_os": ["Windows 10.0.19045", "Windows 11.0.22631"], "service_os": ["RHEL 9.3", "Ubuntu 22.04"],
                   "edge_os": ["Yocto 4.0", "FreeRTOS 10.5", "VxWorks 7", "Zephyr 3.5"], "user_proto": ["TLS1.2"], "service_proto": ["TLS1.2", "OPC-UA"],
                   "edge_proto": ["MQTT3.1.1", "OPC-UA", "Modbus"], "os_pool_all": list(C.OS_POOL) + ["VxWorks 7", "Zephyr 3.5"],
                   "proto_pool_all": list(C.PROTOCOLS) + ["Modbus"]},
        "attacks": {
            "brute_force": {"n": 3, "events": (20, 100), "gap_s": (0.5, 5), "src": "private_internal", "city": "home", "fail_share": (1.0, 1.0),
                            "success_end_p": 0.3, "window": (0.42, 1.0), "victims": "service"},
            "credential_stuffing": {"n": 2, "victims": (15, 40), "n_ips": (1, 3), "src": "private_internal", "city": "home", "spread_s": (5, 60),
                                    "tries": (1, 2), "success_p": 0.02, "window": (0.42, 1.0), "victim_types": "user_service"},
            "impossible_travel": {"n": 6, "gap_h": (0.5, 1.5), "min_km": 5000, "src2": "public", "near_miss": 0.3, "window": (0.42, 1.0), "hops": 1,
                                  "victim_types": "user"},
            "lateral_movement": {"n": 5, "events": (15, 40), "gap_min": (0.5, 3), "hours": tuple(range(24)), "foreign": "ot_all", "cmd": "malicious",
                                 "ip": "own", "window": (0.42, 1.0), "victim_types": "user_service"},
            "device_spoofing": {"n": 10, "events": (10, 40), "gap_min": (1, 10),
                                "variants": {"full_swap": 0.2, "protocol_only": 0.2, "partial_os": 0.15, "partial_mac": 0.15, "clone": 0.3},
                                "ip": "own", "clone_ip_new_p": 0.6, "window": (0.42, 1.0), "victim_types": "edge_service"},
            "low_slow_exfil": {"n": 4, "span_days": (8, 18), "per_day": (2, 6), "hours": [0, 1, 2, 3, 4, 5], "res": "sensitive", "ip": "own",
                               "window": (0.42, 0.75), "victim_types": "service"},
        },
        "benign_drift": {"n": 8, "kind": "device", "start_frac": 0.45, "days": 10, "pool": "edge_device"},
    },
    "P4": {
        "name": "P4", "description": "burst / botnet: very fast high-volume attacks, large distributed credential stuffing, multi-hop travel, compressed exfiltration",
        "n_users": 90, "n_service": 60, "n_devices": 50,
        "roles": ["analyst", "devops", "secops", "data", "admin"], "priv_roles": ["devops", "secops", "admin"],
        "home_cities": MIX_HOME, "foreign_cities": WORLD,
        "resources": {
            "analyst": ["/siem/alerts", "/siem/rules", "/bi/dashboards", "/data/warehouse", "/wiki/runbooks"],
            "devops": ["/k8s/prod", "/k8s/stage", "/cloud/stage", "/cloud/prod", "/ci/main", "/logs/prod", "/vault/keys"],
            "secops": ["/siem/alerts", "/siem/rules", "/iam/users", "/iam/roles", "/vault/keys", "/cloud/prod"],
            "data": ["/data/lake", "/data/warehouse", "/bi/dashboards", "/db/prod", "/notebooks/team"],
            "admin": ["/iam/users", "/iam/roles", "/cloud/prod", "/db/prod", "/vault/keys", "/firewall/policy"],
            "service_account": ["/svc/etl", "/svc/stream", "/svc/scan", "/svc/backup", "/svc/health"],
            "edge_device": ["probe/net", "probe/host", "heartbeat", "telemetry/upload", "fw/check"]},
        "sensitive": ["/iam/roles", "/vault/keys", "/db/prod", "/data/lake", "/cloud/prod"],
        "commands": {"vocab": ["list", "read", "query", "write", "exec", "sudo", "kubectl", "export"], "priv": ["sudo", "exec", "kubectl", "export"],
                     "malicious": ["query", "export", "sudo", "kubectl", "export", "export"], "start": {"devops": "kubectl", "secops": "query"},
                     "default_start": "read", "original_chains": False},
        "hours": {"user_mean": (9.5, 2.2), "user_sd": (1.5, 3.2), "tz_offsets": [0.0, -5.0, 5.5], "shifts": None},
        "events_per_day": {"user": (16, 50), "service": (100, 300), "edge": (120, 350)},
        "ip": {"mode": "mixed", "pool_size": {"user": 3, "service": 2, "edge": 1}, "nat_share": 0.1, "n_shared": 5, "rotate_daily": False,
               "private_bases": ["10", "172.16"], "public_isp": ["52.14", "34.201", "13.107", "104.18"], "travel_ip": "public"},
        "auth": {"fail_rate": {"user": 0.04, "service": 0.02, "edge": 0.01}, "alt_method_p": 0.05, "user_methods": ["password", "token", "biometric"],
                 "service_methods": ["token", "certificate"], "edge_methods": ["certificate"]},
        "confounder": {"rate": 0.08, "travel_p": 0.40, "atypical_res_p": 0.30},
        "device": {"user_os": ["macOS 14.4", "Ubuntu 24.04", "Windows 11.0.22631"], "service_os": ["Ubuntu 22.04", "Ubuntu 24.04"],
                   "edge_os": ["Yocto 4.0", "Ubuntu 24.04"], "user_proto": ["TLS1.3", "SSH2"], "service_proto": ["TLS1.3", "HTTPS"], "edge_proto": ["MQTT3.1.1", "HTTPS"],
                   "os_pool_all": list(C.OS_POOL), "proto_pool_all": list(C.PROTOCOLS)},
        "attacks": {
            "brute_force": {"n": 6, "events": (150, 500), "gap_s": (0.2, 1.5), "src": "public", "city": "foreign", "fail_share": (0.9, 1.0),
                            "success_end_p": 0.5, "window": (0.42, 0.80), "victims": "any"},
            "credential_stuffing": {"n": 3, "victims": (60, 140), "n_ips": (30, 80), "src": "public", "city": "foreign", "spread_s": (2, 30), "tries": (1, 4),
                                    "success_p": 0.04, "window": (0.42, 0.80), "victim_types": "any"},
            "impossible_travel": {"n": 12, "gap_h": (0.3, 1.0), "min_km": 4000, "src2": "public", "near_miss": 0.3, "window": (0.42, 0.80), "hops": 3,
                                  "victim_types": "user"},
            "lateral_movement": {"n": 4, "events": (30, 90), "gap_min": (0.2, 1.5), "hours": tuple(range(24)), "foreign": "all", "cmd": "malicious",
                                 "ip": "own", "window": (0.42, 0.80), "victim_types": "any"},
            "device_spoofing": {"n": 6, "events": (15, 40), "gap_min": (0.5, 4), "variants": {"full_swap": 0.5, "partial_os": 0.25, "clone": 0.25},
                                "ip": "own", "clone_ip_new_p": 0.5, "window": (0.42, 0.80), "victim_types": "edge_service"},
            "low_slow_exfil": {"n": 4, "span_days": (3, 7), "per_day": (6, 12), "hours": [1, 2, 3, 4], "res": "sensitive", "ip": "own", "window": (0.42, 0.75)},
        },
        "benign_drift": {"n": 3, "kind": "resources", "start_frac": 0.50, "days": 12},
    },
}

# controlled drift study: base = P0 constants at reduced size; ONE drift kind applied to a fixed 40% of entities; attacks before / during / after
DRIFT_BASE = {
    "n_users": 100, "n_service": 25, "n_devices": 15,
    "attacks": {
        "brute_force": {"n": 6}, "credential_stuffing": {"n": 3}, "impossible_travel": {"n": 12}, "lateral_movement": {"n": 6},
        "device_spoofing": {"n": 6}, "low_slow_exfil": {"n": 6, "span_days": (4, 6), "window": (0.40, 0.95)},
    },
    "benign_drift": {"n": 0, "kind": "resources", "start_frac": 0.55, "days": 14},
    "attack_periods": [[14.5, 22.0], [22.5, 28.0], [28.5, 35.0]],       # before / during / after (days); incidents are cycled over the periods
    "drift": {"affected_fraction": 0.40, "hours_delta": 3.5, "resource_prob": 0.35, "n_new_resources": 4, "volume_factor": 0.9},
}


REPLACE_KEYS = {"resources", "variants", "start"}        # vocabularies / weight tables are replaced wholesale, never merged with defaults


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k not in REPLACE_KEYS:
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def get_profile(name: str, drift_study: bool = False) -> dict:
    p = _merge(DEFAULTS, PROFILES[name])
    if drift_study:
        p = _merge(p, DRIFT_BASE)
        p["description"] = p["description"] + " [drift-study base: reduced size, attacks before/during/after the drift window]"
    p["name"] = name
    return p
