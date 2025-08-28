import sys
import re
import json
import pandas as pd
from typing import Dict, Any, Tuple


PATTERN_PHONE = re.compile(r'(?<!\d)(?:\+?91[-\s]?)?([6-9]\d{9})(?!\d)')     #all regex patterns goes here
PATTERN_AADHAR = re.compile(r'(?<!\d)(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)')
PATTERN_PASSPORT = re.compile(r'(?<![A-Za-z0-9])([A-PR-WYaprw-y])[ ]?(\d{7})(?![A-Za-z0-9])')
PATTERN_UPI = re.compile(r'([a-zA-Z0-9._-]{2,})@([a-zA-Z]{2,})')
PATTERN_EMAIL = re.compile(r'([a-zA-Z0-9._%+-]{2,})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
PATTERN_IP = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
PATTERN_NAME = re.compile(r'^[A-Za-z]{2,}[ ,]+[A-Za-z]{2,}$')
PATTERN_PINCODE = re.compile(r'(?<!\d)(\d{6})(?!\d)')

PHONE_KEYS = {"phone", "mobile", "contact", "alt_phone", "phone_number"}
ADDR_KEYS = {"address", "shipping_address", "billing_address"}
NAME_KEYS = {"name", "full_name"}
SAFE_IDS = {
    "order_id", "transaction_id", "product_id", "ticket_id", "warehouse_code",
    "customer_id", "gst_number", "state_code", "booking_reference"
}
def mask_phone_number(value: str) -> str:    #here goes masking logic
    match = PATTERN_PHONE.search(value)
    if not match:
        return value
    num = match.group(1)
    hidden = num[:2] + "XXXXXX" + num[-2:]
    return PATTERN_PHONE.sub(hidden, value)
def mask_aadhar_number(value: str) -> str:
    return PATTERN_AADHAR.sub("XXXX-XXXX-XXXX", value)
def mask_passport_number(value: str) -> str:
    return PATTERN_PASSPORT.sub(lambda m: m.group(1).upper() + "XXXXXX" + m.group(2)[-1], value)

def mask_upi_id(value: str) -> str:
    return PATTERN_UPI.sub(lambda m: m.group(1)[:2] + "*" * (len(m.group(1)) - 2) + "@" + m.group(2), value)

def mask_email_id(value: str) -> str:
    return PATTERN_EMAIL.sub(lambda m: m.group(1)[:2] + "*" * (len(m.group(1)) - 2) + "@" + m.group(2), value)

def mask_ip_addr(value: str) -> str:
    return PATTERN_IP.sub(lambda m: ".".join(m.group(1).split(".")[:2]) + ".*.*", value)

def anonymize_name(value: str) -> str:
    parts = value.strip().split()
    return " ".join(p[0].upper() + "XXX" for p in parts if p)

def looks_like_phone(key: str, val: Any) -> bool:        # here detection logic

    s = str(val)
    if key in SAFE_IDS:
        return False
    if key.lower() in PHONE_KEYS and PATTERN_PHONE.search(s):
        return True
    digits = re.sub(r'\D', '', s)
    return len(digits) == 10 and PATTERN_PHONE.search(s) is not None


def has_aadhar(val: Any) -> bool:
    return isinstance(val, str) and PATTERN_AADHAR.search(val)
def has_passport(val: Any) -> bool:
    return isinstance(val, str) and PATTERN_PASSPORT.search(val)
def has_upi(val: Any) -> bool:
    return isinstance(val, str) and PATTERN_UPI.search(val)


def has_email(val: Any) -> bool:
    return isinstance(val, str) and PATTERN_EMAIL.search(val)




def valid_name(val: Any) -> bool:
    return isinstance(val, str) and PATTERN_NAME.match(val.strip())
def has_ip(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    match = PATTERN_IP.search(val)
    if not match:
        return False
    parts = match.group(1).split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def looks_like_address(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    if not PATTERN_PINCODE.search(val):
        return False
    keywords = ["street", "road", "lane", "sector", "block", "apt", "apartment", "floor", "phase"]
    return any(k in val.lower() for k in keywords) and bool(re.search(r'\d+', val))





def redact_record(record: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    pii_detected = False
    combined_signals = set()
    redacted = dict(record)

    for k, v in record.items():
        key = str(k).lower()
        sval = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)

        if looks_like_phone(key, sval):
            pii_detected = True
            redacted[k] = mask_phone_number(sval)
            continue
        if has_aadhar(sval):
            pii_detected = True
            redacted[k] = mask_aadhar_number(sval)
            continue
        if has_passport(sval):
            pii_detected = True
            redacted[k] = mask_passport_number(sval)
            continue
        if has_upi(sval):
            pii_detected = True
            redacted[k] = mask_upi_id(sval)
            continue

        if (key in NAME_KEYS and valid_name(sval)) or (key in {"first_name", "last_name"} and sval.strip()):
            combined_signals.add("name")
        if has_email(sval):
            combined_signals.add("email")
        if key in ADDR_KEYS and looks_like_address(sval):
            combined_signals.add("address")
        if key == "device_id" and isinstance(sval, str) and len(sval) >= 6:
            combined_signals.add("device")
        if key == "ip_address" and has_ip(sval):
            combined_signals.add("ip")

    score = len(combined_signals)
    if score >= 2:
        if (("device" in combined_signals or "ip" in combined_signals) and not {"name", "email", "address"} & combined_signals):
            is_pii = pii_detected
        else:
            is_pii = True
    else:
        is_pii = pii_detected

    if is_pii and score > 0:
        for k, v in record.items():
            key = str(k).lower()
            sval = str(v)

            if key in NAME_KEYS and valid_name(sval):
                redacted[k] = anonymize_name(sval)
            elif key in {"first_name", "last_name"} and sval:
                redacted[k] = sval[0].upper() + "XXX"
            elif has_email(sval):
                redacted[k] = mask_email_id(sval)
            elif key in ADDR_KEYS and looks_like_address(sval):
                redacted[k] = "[REDACTED_ADDRESS]"
            elif key == "ip_address" and has_ip(sval):
                redacted[k] = mask_ip_addr(sval)
            elif key == "device_id" and len(sval) >= 6:
                redacted[k] = "[REDACTED_DEVICE_ID]"

    if is_pii:
        for k, v in list(redacted.items()):
            if not isinstance(v, str):
                continue
            val = mask_phone_number(v)
            val = mask_aadhar_number(val)
            val = mask_passport_number(val)
            val = mask_upi_id(val)
            val = mask_email_id(val)
            val = mask_ip_addr(val)
            redacted[k] = val

    return is_pii, redacted
def process_dataset(input_csv: str, output_csv: str):           # here goes CSV file
    df = pd.read_csv(input_csv)
    cols = {c.lower(): c for c in df.columns}
    if "record_id" not in cols or ("data_json" not in cols and "data" not in cols):
        raise ValueError("CSV must include columns: record_id, data_json")
    rid_col = cols["record_id"]
    data_col = cols.get("data_json", cols.get("data"))

    results = []
    for _, row in df.iterrows():
        rid = row[rid_col]
        raw = row[data_col]
        try:
            data = json.loads(raw)
        except Exception:
            try:
                data = json.loads(raw.replace("'", '"'))
            except Exception:
                data = {"__raw__": str(raw)}

        is_pii, red = redact_record(data)
        results.append({
            "record_id": rid,
            "redacted_data_json": json.dumps(red, ensure_ascii=False),
            "is_pii": bool(is_pii)
        })

    pd.DataFrame(results, columns=["record_id", "redacted_data_json", "is_pii"]).to_csv(output_csv, index=False)





def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py data.csv")
        sys.exit(1)

    in_file = sys.argv[1]
    out_file = "redacted_output_aryanpro00715.csv"
    process_dataset(in_file, out_file)
    print(f"output: {out_file}")
if __name__ == "__main__":
    main()
