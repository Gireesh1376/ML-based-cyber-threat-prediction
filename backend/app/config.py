from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
MODELS_DIR = ROOT / "models"
METRICS_PATH = MODELS_DIR / "metrics.json"
ALERTS_PATH = MODELS_DIR / "demo_alerts.json"

NSL_KDD_TRAIN_URL = (
    "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt"
)
NSL_KDD_TEST_URL = (
    "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt"
)

FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

ATTACK_FAMILY = {
    "normal": "benign",
    "back": "dos",
    "land": "dos",
    "neptune": "dos",
    "pod": "dos",
    "smurf": "dos",
    "teardrop": "dos",
    "apache2": "dos",
    "udpstorm": "dos",
    "processtable": "dos",
    "worm": "dos",
    "mailbomb": "dos",
    "satan": "probe",
    "ipsweep": "probe",
    "nmap": "probe",
    "portsweep": "probe",
    "mscan": "probe",
    "saint": "probe",
    "guess_passwd": "r2l",
    "ftp_write": "r2l",
    "imap": "r2l",
    "phf": "r2l",
    "multihop": "r2l",
    "warezmaster": "r2l",
    "warezclient": "r2l",
    "spy": "r2l",
    "xlock": "r2l",
    "xsnoop": "r2l",
    "snmpguess": "r2l",
    "snmpgetattack": "r2l",
    "httptunnel": "r2l",
    "sendmail": "r2l",
    "named": "r2l",
    "buffer_overflow": "u2r",
    "loadmodule": "u2r",
    "rootkit": "u2r",
    "perl": "u2r",
    "sqlattack": "u2r",
    "xterm": "u2r",
    "ps": "u2r",
}

# ---------------------------------------------------------------------------
# Problem 3: ASSET criticality (literature-review requirement 4.1).
#
# Asset criticality = how much damage an.event on the TARGET system would do.
# This is NOT the same as threat-family severity (how dangerous the attack
# itself is). The same probe against a DNS / auth backend matters more than
# against a guest web server.
#
# Scale: continuous in [0, 1], banded Low (0-0.24), Medium (0.25-0.49),
# High (0.50-0.74), Critical (0.75-1.0). Mapped per NSL-KDD service name below
# using the well-known semantics of each protocol/service (auth backends,
# remote shell/mail infra and DNS are the highest-impact assets in a classic
# enterprise DMZ; transient UDP services and discard/echo utilities are low).
# Unknown services (not in this map) must NOT silently be treated as
# unimportant: they fall back to the neutral ASSET_UNKNOWN_FALLBACK value and
# are flagged, and the Alerts UI shows a "Review" tier floor for them.
SERVICE_CRITICALITY: dict[str, float] = {
    # --- Critical: identity, remote access, name resolution ---
    "login": 0.95,
    "shell": 1.00,
    "exec": 0.95,
    "su": 1.00,
    "telnet": 0.95,
    "rje": 0.90,
    "ssh": 0.95,
    "auth": 0.90,
    "domain": 0.90,
    "domain_u": 0.85,
    "name": 0.85,
    "netbios_ns": 0.80,
    "pop_3": 0.75,
    "pop_2": 0.70,
    "smtp": 0.80,
    "imap4": 0.80,
    "ftp": 0.75,
    "ftp_data": 0.70,
    "hostnames": 0.75,
    "hostsources": 0.75,
    "ntp_u": 0.70,
    "uucp": 0.70,
    "uucp_path": 0.70,
    "pgp": 0.75,
    "whois": 0.65,
    "nntp": 0.65, "nnsp": 0.65,
    # --- High: file transfer / windows networking / databases ---
    "efs": 0.80, "iso_tsap": 0.70, "netbios_ssn": 0.75, "netbios_dgm": 0.70,
    "bgp": 0.75, "hostnames": 0.75, "hostsources": 0.75, "csnet_ns": 0.75,
    "uucp": 0.70, "uucp_path": 0.70, "ntp_u": 0.70, "bgp": 0.75,
    "sql_net": 0.85, "klogin": 0.90, "kshell": 0.90, "rlogin": 0.90,
    "ssh": 0.95, "ssh_error": 0.90, "tenet": 0.85, "remote_job": 0.80,
    # --- Medium: web and misc services ---
    "http": 0.55, "http_2784": 0.55, "http_8001": 0.55, "http_443": 0.60,
    "http-mgmt": 0.55, "gopher": 0.55, "X11": 0.65, "Z39_50": 0.60,
    "IRC": 0.60, "ctf": 0.65, "netstat": 0.60, "printer": 0.55, "systat": 0.55,
    "link": 0.50, "pm_dump": 0.50,
    # --- Low: transient / utility services ---
    "tftp_u": 0.45, "urh_i": 0.45, "urp_i": 0.45, "red_i": 0.45,
    "harvest": 0.45, "daytime": 0.45, "aol": 0.40,
    "echo": 0.35, "discard": 0.35, "chargen": 0.35,
    # --- Added after the cross-check: the 13 NSL-KDD services that were previously
    # unmapped (31% of test flows, incl. the very common private/other/ecr_i/eco_i).
    # Design-choice values from protocol semantics, same banding as above.
    "private": 0.50, "other": 0.50,            # ephemeral/unspecified ports: neutral
    "eco_i": 0.40, "ecr_i": 0.40, "tim_i": 0.40,  # ICMP echo/timestamp: low
    "finger": 0.60, "time": 0.45, "mtp": 0.55, "vmnet": 0.60,
    "courier": 0.65, "sunrpc": 0.75, "supdup": 0.80, "ldap": 0.85,
}
# Single source of truth (priority.py imports this). Was 0.55 here vs 0.5 in
# priority.py, so evaluate.py scored unmapped services differently from the
# deployed detector; 0.5 is the value the deployed model and README use.
ASSET_UNKNOWN_FALLBACK = 0.5

# Anything not mapped above gets this neutral criticality but is flagged so
# callers can enforce a Review tier floor instead of silently assuming low risk.
ZERO_DAY_LABELS = {
    "mscan",
    "saint",
    "apache2",
    "udpstorm",
    "processtable",
    "mailbomb",
    "worm",
    "httptunnel",
    "sqlattack",
    "xterm",
    "ps",
    "named",
    "sendmail",
    "snmpguess",
    "xlock",
}
