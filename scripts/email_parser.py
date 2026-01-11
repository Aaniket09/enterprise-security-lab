#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
SOC LAB - EMAIL PARSER & TELEMETRY LOGGER
--------------------------------------------------------------------------------
Author: Aniket Agarwal
Description: 
    Intercepts emails from Postfix, parses headers/body/attachments into JSON 
    for Splunk ingestion, and then re-injects the email back to Postfix for delivery.
    
    Includes 'Lab Simulation' logic to rewrite local domains to malicious ones
    (e.g., internetbadguys.com) to test Threat Intelligence workflows.
"""

import sys
import email
import json
import datetime
import hashlib
import re
import smtplib
from email.header import decode_header

# --- CONFIGURATION ---
LOG_FILE = "/var/log/splunk_full_email.log"
FORWARD_HOST = "127.0.0.1"
FORWARD_PORT = 10026  # Postfix re-injection port
EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
TEST_MALICIOUS_DOMAIN = "internetbadguys.com"


def get_file_hash(file_data):
    """Calculates SHA256 hash of file data."""
    sha256_hash = hashlib.sha256()
    # Handle empty files gracefully
    sha256_hash.update(file_data or b"")
    return sha256_hash.hexdigest()


def clean_text(text_data):
    """Decodes MIME headers and converts byte strings to plain strings."""
    if not text_data: 
        return "Unknown"
    try:
        decoded_list = decode_header(text_data)
        clean_out = ""
        for token, charset in decoded_list:
            if isinstance(token, bytes):
                clean_out += token.decode(charset or 'utf-8', errors='ignore')
            else:
                clean_out += str(token)
        return clean_out.strip()
    except Exception:
        return str(text_data)


def parse_and_forward():
    # 1. READ RAW EMAIL FROM STDIN
    try:
        raw_content = sys.stdin.read()
        if not raw_content: 
            return
    except Exception:
        return

    # 2. PARSE & LOG LOGIC
    try:
        msg = email.message_from_string(raw_content)

        # Clean Headers
        subject_raw = clean_text(msg.get("Subject", "Unknown"))
        from_raw = clean_text(msg.get("From", "Unknown"))

        # --- LAB FIX: DOMAIN SIMULATION ---
        # If the sender is from a local lab domain, rewrite it in the LOGS
        # so Splunk and VirusTotal see a "real" malicious domain.
        if ".local" in from_raw:
            # Replace the domain part with the test domain
            # e.g., "john.wick@lab.local" -> "john.wick@internetbadguys.com"
            from_raw = re.sub(r"@[\w\d\.\-]+\.local", f"@{TEST_MALICIOUS_DOMAIN}", from_raw)
            # Add a tag to the subject so you know it was modified
            subject_raw += " [LAB_SIM]"

        data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "log_type": "email_telemetry",
            "subject": subject_raw,
            "from": from_raw,
            "reply_to": clean_text(msg.get("Reply-To", "Unknown")),
            "return_path": clean_text(msg.get("Return-Path", "Unknown")),
            "received_chain": str(msg.get_all("Received")),
            "body": "",
            "attachments": []
        }

        # IP Extraction (X-Originating-IP or fallback to Received headers)
        data["x_originating_ip"] = msg.get("X-Originating-IP") or "Unknown"
        if data["x_originating_ip"] == "Unknown" and data["received_chain"]:
            ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", data["received_chain"])
            if ip_match: 
                data["x_originating_ip"] = ip_match.group(1)

        # Attachment & Body Extraction
        if msg.is_multipart():
            for part in msg.walk():
                cdisp = str(part.get("Content-Disposition"))
                filename = clean_text(part.get_filename())

                # Handle files
                if filename and filename != "Unknown":
                    file_payload = part.get_payload(decode=True)
                    if file_payload is not None:
                        file_hash = get_file_hash(file_payload)
                        # Force EICAR hash for lab testing if filename looks suspicious
                        if "invoice" in filename.lower() or "exe" in filename.lower():
                            file_hash = EICAR_HASH
                        data["attachments"].append({"filename": filename, "sha256": file_hash})

                # Check for "attachment" in Content-Disposition if filename is missing
                elif "attachment" in cdisp:
                    filename = "invoice_copy.exe"
                    file_payload = part.get_payload(decode=True)
                    if file_payload is not None:
                        data["attachments"].append({"filename": filename, "sha256": EICAR_HASH})

                # Handle Body Text
                elif part.get_content_type() in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        data["body"] = payload.decode('utf-8', errors='ignore')[:1000]
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                data["body"] = payload.decode('utf-8', errors='ignore')[:1000]

        # Log to file (JSON format)
        # Avoid logging localhost loop traffic to reduce noise
        if data["x_originating_ip"] != "127.0.0.1":
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(data) + "\n")

    except Exception as e:
        with open("/var/log/email_parser_error.log", "a") as f:
            f.write(f"Logging Error: {str(e)}\n")

    # 3. RE-INJECT EMAIL TO POSTFIX
    try:
        sender = sys.argv[1] if len(sys.argv) > 1 else "unknown@lab.local"
        recipient = sys.argv[2] if len(sys.argv) > 2 else "unknown@lab.local"
        
        with smtplib.SMTP(FORWARD_HOST, FORWARD_PORT) as server:
            server.sendmail(sender, recipient, raw_content)
            
    except Exception as e:
        with open("/var/log/email_parser_error.log", "a") as f:
            f.write(f"Forwarding Error: {str(e)}\n")

if __name__ == "__main__":
    parse_and_forward()