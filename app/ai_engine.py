from google import genai
from app.config import GEMINI_API_KEY, GEMINI_MODEL
import json
import re
import logging

logger = logging.getLogger("fortigate_ai")

DEFAULT_OUTPUT = {
    "issue_summary": "Unable to determine exact issue from provided logs.",
    "severity": "medium",
    "root_cause": "Insufficient or ambiguous packet-sniffer evidence.",
    "affected_hosts": [],
    "firewall_policy": "unknown",
    "action_required": "Collect more targeted sniffer output and policy/session evidence.",
    "recommendations": [
        "Capture both directions on the same flow with a stricter filter.",
        "Correlate packet sniffer lines with forward traffic logs and policy IDs.",
        "Validate route lookup, NAT behavior, and session state for the affected flow."
    ],
    "next_cli_checks": [
        "diagnose sniffer packet any 'host <src_ip> and host <dst_ip>' 4 0 a",
        "diagnose debug flow filter addr <src_or_dst_ip>",
        "diagnose debug flow show function-name enable; diagnose debug enable",
        "get router info routing-table details <dst_ip>",
        "diagnose sys session list"
    ],
    "confidence_score": 45,
    "related_log_lines": []
}

KEYS = set(DEFAULT_OUTPUT.keys())

def _create_client():
    if not GEMINI_API_KEY:
        return None
    try:
        return genai.Client(api_key=GEMINI_API_KEY)
    except Exception:
        logger.exception("Failed to initialize Gemini client; fallback mode will be used")
        return None


client = _create_client()

SYSTEM_PROMPT = """
You are a senior FortiGate network security engineer.

Analyze FortiGate CLI packet sniffer logs and determine the root cause.

Rules:
- Return STRICT JSON only.
- No explanations outside JSON.
- Extract only factual information.
- If missing, use "unknown".
- Severity must be: low, medium, high, or critical.
- Confidence score must be 0-100.
- Focus on packet path, NAT/policy/routing/session/TCP behavior.
- Recommendations must be actionable and FortiGate-specific.

JSON format:

{
  "issue_summary": "",
  "severity": "",
  "root_cause": "",
  "affected_hosts": [],
  "firewall_policy": "",
  "action_required": "",
  "recommendations": [],
  "next_cli_checks": [],
  "confidence_score": 0,
  "related_log_lines": []
}
"""

def _extract_json(text_output: str):
    text_output = text_output.strip()
    if text_output.startswith("```"):
        text_output = re.sub(r"^```(?:json)?", "", text_output).strip()
        text_output = re.sub(r"```$", "", text_output).strip()

    start = text_output.find("{")
    end = text_output.rfind("}")
    if start >= 0 and end > start:
        text_output = text_output[start:end + 1]

    return json.loads(text_output)


def _infer_firewall_policy(logs: str) -> str:
    policy_patterns = [
        r"policyid=(\d+)",
        r"policy\s*id\s*[:=]\s*(\d+)",
        r"policy\s*(\d+)"
    ]
    for pattern in policy_patterns:
        match = re.search(pattern, logs, re.IGNORECASE)
        if match:
            return match.group(1)
    return "unknown"


def _normalize_output(parsed: dict):
    normalized = dict(DEFAULT_OUTPUT)

    for key in KEYS:
        if key in parsed and parsed[key] is not None:
            normalized[key] = parsed[key]

    normalized["severity"] = str(normalized["severity"]).lower().strip()
    if normalized["severity"] not in {"low", "medium", "high", "critical"}:
        normalized["severity"] = "medium"

    try:
        normalized["confidence_score"] = int(normalized["confidence_score"])
    except Exception:
        normalized["confidence_score"] = DEFAULT_OUTPUT["confidence_score"]

    normalized["confidence_score"] = max(0, min(100, normalized["confidence_score"]))

    for list_field in ["affected_hosts", "recommendations", "next_cli_checks", "related_log_lines"]:
        value = normalized.get(list_field, [])
        if not isinstance(value, list):
            normalized[list_field] = [str(value)] if value else []
        else:
            normalized[list_field] = [str(item) for item in value][:10]

    for text_field in ["issue_summary", "root_cause", "firewall_policy", "action_required"]:
        normalized[text_field] = str(normalized.get(text_field, "unknown")).strip() or "unknown"

    return normalized


def _heuristic_analysis(logs: str):
    output = dict(DEFAULT_OUTPUT)
    lines = [line.strip() for line in logs.splitlines() if line.strip()]

    patterns = [
        (r"deny|blocked|iprope_in_check|policy\s*0", "Traffic is likely denied by firewall policy.", "high", [
            "Create or adjust an allow policy for the source/destination/service pair.",
            "Verify policy order and ensure no deny rule matches first.",
            "Confirm the correct incoming and outgoing interfaces are used in the policy."
        ]),
        (r"no\s+route|reverse\s+path\s+check\s+fail|rpf", "Routing issue detected for return path or destination lookup.", "high", [
            "Add/fix static or dynamic route for the destination network.",
            "Validate gateway reachability and route priority/distance.",
            "Check asymmetric routing and source validation settings."
        ]),
        (r"tcp\s*rst|reset", "Connection is being actively reset by one endpoint or intermediate device.", "medium", [
            "Identify which side sends the RST using packet direction and interface mapping.",
            "Review server-side service logs and application listener status.",
            "Validate security profiles and upstream controls that may terminate sessions."
        ]),
        (r"retransmission|duplicate\s+ack|out\s+of\s+order|timeout", "Packet loss or unstable path likely causing TCP instability.", "medium", [
            "Check interface errors, MTU/MSS settings, and WAN quality.",
            "Test path stability and packet loss between endpoints.",
            "Inspect IPS/UTM profiles for unintended packet drops."
        ]),
        (r"syn\s*sent|syn\s*$", "Handshake not completed; server or path may be unreachable.", "medium", [
            "Confirm destination server is listening on the expected port.",
            "Validate NAT/VIP and upstream ACL rules.",
            "Trace return traffic to ensure SYN-ACK is not blocked."
        ])
    ]

    lowered = "\n".join(lines).lower()
    for regex, root_cause, severity, recs in patterns:
        if re.search(regex, lowered):
            output["root_cause"] = root_cause
            output["severity"] = severity
            output["issue_summary"] = root_cause
            output["action_required"] = recs[0]
            output["recommendations"] = recs
            break

    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", logs)
    output["affected_hosts"] = sorted(list(set(ip_matches)))[:6]
    output["related_log_lines"] = lines[:8]
    output["firewall_policy"] = _infer_firewall_policy(logs)
    output["confidence_score"] = 60 if output["root_cause"] != DEFAULT_OUTPUT["root_cause"] else 45

    return output


def analyze_logs(logs: str):

    if not logs or not logs.strip():
        empty_result = dict(DEFAULT_OUTPUT)
        empty_result["issue_summary"] = "No log content received."
        empty_result["root_cause"] = "No packet sniffer lines provided."
        empty_result["action_required"] = "Paste FortiGate CLI packet sniffer output and re-run analysis."
        empty_result["confidence_score"] = 10
        return empty_result

    full_prompt = f"""
{SYSTEM_PROMPT}

Analyze the following FortiGate CLI packet sniffer logs:

{logs}
"""

    try:
        if client is None:
            logger.info("Using heuristic mode (Gemini client unavailable)")
            return _heuristic_analysis(logs)

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=full_prompt
        )

        text_output = (response.text or "").strip()
        parsed = _extract_json(text_output)
        return _normalize_output(parsed)
    except Exception:
        logger.exception("AI analysis failed; returning heuristic analysis")
        return _heuristic_analysis(logs)