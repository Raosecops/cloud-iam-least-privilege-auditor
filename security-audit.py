import os
import json

POLICIES_DIR = "policies"
DANGEROUS_PATTERNS = ["*", "s3:*", "iam:*", "logs:*"]

print("=" * 60)
print("  ROASECOPS ENTERPRISE IAM SECURITY AUDIT ENGINE")
print("=" * 60)

audit_failed = False

for filename in sorted(os.listdir(POLICIES_DIR)):
    if filename.endswith(".json"):
        filepath = os.path.join(POLICIES_DIR, filename)
        print(f"\n[*] Scanning policy file: {filename}")
        
        with open(filepath, "r") as f:
            try:
                policy_data = json.load(f)
            except Exception as e:
                print(f"    [X] ERROR: Failed to parse JSON - {e}")
                audit_failed = True
                continue
                
        # Check statements for dangerous wildcards and privilege escalation
        for idx, statement in enumerate(policy_data.get("Statement", [])):
            sid = statement.get("Sid", f"Statement-{idx}")
            effect = statement.get("Effect", "Allow")
            actions = statement.get("Action", [])
            resource = statement.get("Resource", "")
            
            if isinstance(actions, str):
                actions = [actions]
                
            # Evaluate risks
            for action in actions:
                if effect == "Allow" and (action in DANGEROUS_PATTERNS or "*" in action) and resource == "*":
                    print(f"    [!] HIGH SEVERITY FINDING [{sid}]:")
                    print(f"        Action '{action}' combined with Resource '*' creates privilege escalation or global blast radius!")
                    audit_failed = True
                elif effect == "Allow":
                    print(f"    [+] PASSED [{sid}]: Action '{action}' is properly scoped.")

print("\n" + "=" * 60)
if audit_failed:
    print("[-] AUDIT RESULT: SECURITY VULNERABILITIES DETECTED.")
    print("=" * 60)
else:
    print("[+] AUDIT RESULT: ALL POLICIES COMPLY WITH LEAST-PRIVILEGE.")
    print("=" * 60)
