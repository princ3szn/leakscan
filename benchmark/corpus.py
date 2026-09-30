import random
import string
from dataclasses import dataclass

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
B64URL = ALNUM + "_-"
HEX = "0123456789abcdef"


@dataclass(frozen=True)
class Case:
    filename: str
    lines: tuple
    secret_lines: frozenset  # 1-based line numbers that hold a real secret
    note: str


def build_cases() -> list[Case]:
    rng = random.Random(1337)

    def rand(n, alphabet=ALNUM):
        return "".join(rng.choice(alphabet) for _ in range(n))

    def pos(filename, lines, at, note):
        return Case(filename, tuple(lines), frozenset(at), note)

    def neg(filename, lines, note):
        return Case(filename, tuple(lines), frozenset(), note)

    aws1 = "AKIA" + rand(16, UPPER_DIGITS)
    aws2 = "ASIA" + rand(16, UPPER_DIGITS)
    ghp1 = "ghp_" + rand(36)
    ghp2 = "ghp_" + rand(36)
    fine = "github_pat_" + rand(22) + "_" + rand(59)
    stripe = "sk_live_" + rand(24)
    google = "AIza" + rand(35, B64URL)
    slack = "xoxb-" + rand(12, string.digits) + "-" + rand(24)
    jwt = "eyJ" + rand(20, B64URL) + ".eyJ" + rand(20, B64URL) + "." + rand(30, B64URL)
    pem = ["-----BEGIN RSA " + "PRIVATE KEY-----"]
    pem += [rand(64) for _ in range(3)]
    pem += ["-----END RSA " + "PRIVATE KEY-----"]
    pw_py, pw_json, pw_yaml, pw_js = rand(16), rand(24), rand(20), rand(20)
    weak = "hunter2" * 2
    unquoted = rand(14)
    db_pw = rand(12)
    uuid = "-".join(rand(n, HEX) for n in (8, 4, 4, 4, 12))

    return [
        # ---- real secrets (easy) ----
        pos("config_aws.py", ["import os", "", f'AWS_KEY = "{aws1}"'], {3}, "AWS key in Python"),
        pos("aws.env", [f"AWS_ACCESS_KEY_ID={aws2}", "AWS_REGION=eu-west-1"], {1}, "AWS key in .env"),
        pos("client.js", ["const url = '/api';", f'const token = "{ghp1}";'], {2}, "GitHub PAT in JS"),
        pos("ci.yaml", ["name: deploy", f"token: {ghp2}"], {2}, "GitHub PAT in YAML, unquoted"),
        pos("fine_grained.txt", [f"GH_TOKEN={fine}"], {1}, "GitHub fine-grained PAT"),
        pos("billing.py", [f'STRIPE_KEY = "{stripe}"'], {1}, "Stripe live key"),
        pos("maps.js", [f'const KEY = "{google}";'], {1}, "Google API key"),
        pos("notify.py", [f'SLACK_TOKEN = "{slack}"'], {1}, "Slack token"),
        pos("deploy_key.pem", pem, {1}, "Private key block"),
        pos("request.http", ["POST /login", f'headers = {{"Authorization": "Bearer {jwt}"}}'], {2}, "JWT in header"),
        pos("settings.py", [f'DB_PASSWORD = "{pw_py}"'], {1}, "Generic password, Python"),
        pos("config.json", ["{", f'  "api_key": "{pw_json}"', "}"], {2}, "Generic api_key, JSON"),  # leakscan:ignore
        pos("secrets.yml", [f"secret: '{pw_yaml}'"], {1}, "Generic secret, YAML"),  # leakscan:ignore
        pos("auth.js", [f'const authToken = "{pw_js}";'], {1}, "Generic token, JS"),
        # ---- real secrets (hard) ----
        pos("weak_pw.py", [f'password = "{weak}"'], {1}, "hard: real but low-entropy password"),
        pos("db.env", [f"DB_PASSWORD={unquoted}"], {1}, "hard: unquoted password assignment"),
        pos("conn.env", ["DATABASE_URL=" + "postgres" + "://admin:" + db_pw + "@db.internal:5432/app"], {1}, "hard: password inside URL"),
        # ---- not secrets ----
        neg("placeholder.py", ['api_key = "your_api_key_here"'], "placeholder"),
        neg("vault.yaml", ['secret = "${SECRET_FROM_VAULT}"'], "template variable"),
        neg("env_read.py", ['api_key = os.environ["API_KEY"]'], "reads from environment"),
        neg("template.txt", ['password = "<password>"'], "angle-bracket placeholder"),
        neg("label.js", ['password_label = "Enter your password"'], "UI label"),
        neg("i18n.json", ['{"password": "Passwort"}'], "translation string"),
        neg("logo.js", ['logo = "data:image/png;base64,' + rand(80, B64URL) + '"'], "base64 image data"),
        neg("hashes.py", ['sha256 = "' + rand(64, HEX) + '"'], "file hash"),
        neg("ids.py", [f'request_id = "{uuid}"'], "UUID"),
        neg("token_call.py", ["token = get_token()"], "function call"),
        neg("default.py", ['secret = "changeme"'], "common default value"),
        neg("README.md", ["# Setup", "Example: AKIA" + "IOSFODNN7EXAMPLE"], "documented AWS example key"),
        neg("fixtures.py", ['password = "test-password-123"'], "test fixture value"),  # leakscan:ignore
        neg("limits.py", ['secret_key_length = "1234567890"'], "numeric config value"),  # leakscan:ignore
    ]
