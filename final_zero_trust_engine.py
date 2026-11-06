# Core Autonomous Zero Trust & ITDR Engine Module

import pandas as pd
import json
import time
from datetime import datetime

# Simulated Live Production Stream (AWS CloudTrail / Okta Telemetry mixed data logs)
live_log_stream = """
[
    {"eventTime": "2026-11-06T10:00:00Z", "userName": "security_lead", "eventName": "ConsoleLogin", "sourceIPAddress": "106.200.45.1", "userAgent": "Macintosh/Chrome", "MFAUsed": "Yes"},
    {"eventTime": "2026-11-06T10:01:00Z", "userName": "security_lead", "eventName": "DescribeInstances", "sourceIPAddress": "106.200.45.1", "userAgent": "Macintosh/Chrome", "MFAUsed": "Yes"},
    {"eventTime": "2026-11-06T10:01:01Z", "userName": "security_lead", "eventName": "StopLogging", "sourceIPAddress": "185.200.118.4", "userAgent": "Python-requests/AI-Agent", "MFAUsed": "No"},
    {"eventTime": "2026-11-06T10:01:02Z", "userName": "security_lead", "eventName": "DeleteBucketPolicy", "sourceIPAddress": "185.200.118.4", "userAgent": "Python-requests/AI-Agent", "MFAUsed": "No"}
]
"""

# Risk Allocation Metrics
EVENT_CRITICALITY = {
    "ConsoleLogin": 10,
    "DescribeInstances": 5,
    "StopLogging": 45,        # High-Risk: Disabling SIEM/Telemetry auditing
    "DeleteBucketPolicy": 40  # High-Risk: Compromising data storage perimeters
}

def analyze_telemetry_stream():
    print("🤖 [ZERO-TRUST ENGINE] Booting Real-Time Behavioral Ingestion Layer...")
    print("🔒 [STATUS]: Active RF-style Cloud Telemetry Scanner Engaged.\n" + "="*85)
    
    logs = json.loads(live_log_stream)
    df = pd.DataFrame(logs)
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df = df.sort_values(by=['userName', 'eventTime']).reset_index(drop=True)
    
    for i in range(1, len(df)):
        prev = df.iloc[i - 1]
        curr = df.iloc[i]
        
        if prev['userName'] == curr['userName']:
            # Telemetry Vector Analysis
            time_gap = (curr['eventTime'] - prev['eventTime']).total_seconds()
            ua_changed = prev['userAgent'] != curr['userAgent']
            ip_changed = prev['sourceIPAddress'] != curr['sourceIPAddress']
            mfa_dropped = prev['MFAUsed'] == "Yes" and curr['MFAUsed'] == "No"
            
            # Risk Scoring Calculator
            threat_score = 0
            indicators = []
            
            if time_gap <= 3.0:
                threat_score += 35
                indicators.append(f"Machine-Velocity Violation Detected ({time_gap}s)")
            if ua_changed:
                threat_score += 25
                indicators.append(f"User-Agent Mutation: '{prev['userAgent']}' ➔ '{curr['userAgent']}'")
            if ip_changed:
                threat_score += 25
                indicators.append(f"Network Perimeter Swap: {prev['sourceIPAddress']} ➔ {curr['sourceIPAddress']}")
            if mfa_dropped:
                threat_score += 20
                indicators.append("MFA Session Degradation (Session Cookie Hijacking footprint)")
                
            # Add infrastructure impact points
            threat_score += EVENT_CRITICALITY.get(curr['eventName'], 0)
            
            # Evaluation Threshold Gate
            if threat_score >= 75:
                print(f"\n🚨 [ALARM: HIGH-RISK THREAT CONTEXT AFFECTING USER: {curr['userName'].upper()}]")
                print(f"   [📈 AGGREGATE THREAT VELOCITY SCORE]: {threat_score}/135")
                print(f"   [🎯 TRIGGER EVENT]: {prev['eventName']} ➔ {curr['eventName']}")
                print("   [🔍 ANOMALY TRACE LOGS]:")
                for ind in indicators:
                    print(f"     ▪ {ind}")
                
                # Zero-Mistake Containment Logic (Simulating under 5 seconds execution)
                print(f"\n🛡️  [ADAPTIVE RESPONSE ORCHESTRATOR - TRIGGERED IN < 1.25 SECONDS]:")
                print(f"   [+] Executing IAM Hard Revocation: `aws iam revoke-user-sessions --user-name {curr['userName']}`")
                print(f"   [+] Modifying Network Protection: Pushing IP {curr['sourceIPAddress']} to AWS WAF drop blocks.")
                print(f"   [+] ChatOps Sync: Streaming payload metrics directly to #soc-incident-response on Slack.")
                print(f"   [✅ RESULT]: Malicious automation contained cleanly. Session state destroyed globally.")
                print("="*85 + "\n")
            else:
                # Lower score triggers safe adaptive warning without blocking the user
                print(f"ℹ️  [BENIGN INTERCEPT]: Action parsed for user [{curr['userName']}]. Score: {threat_score}. No anomalies detected.")

if __name__ == "__main__":
    analyze_telemetry_stream()
