import json

# Mock cloud environment data simulating AWS S3 buckets and IAM policies
mock_cloud_infrastructure = {
    "storage_buckets": [
        {"name": "company-financial-reports", "public_access": False, "encryption": True},
        {"name": "customer-pii-backup", "public_access": True, "encryption": False},  # Violation!
        {"name": "public-marketing-assets", "public_access": True, "encryption": True} # Expected public, but check encryption
    ],
    "iam_policies": [
        {"policy_name": "AdminAccess", "resource": "*", "privilege_level": "Full"}, # Violation risk!
        {"policy_name": "ReadOnlyLogs", "resource": "arn:aws:s3:::logs-*", "privilege_level": "Read"}
    ]
}

def audit_s3_buckets(buckets):
    print("--- [ITGC] Auditing S3 Storage Buckets ---")
    violations = 0
    for bucket in buckets:
        print(f"Checking bucket: {bucket['name']}...")
        if bucket["public_access"]:
            print(f"  [!] DEFICIENCY FOUND: Bucket '{bucket['name']}' is publicly accessible!")
            violations += 1
        if not bucket["encryption"]:
            print(f"  [!] DEFICIENCY FOUND: Bucket '{bucket['name']}' lacks server-side encryption!")
            violations += 1
    return violations

def audit_iam_policies(policies):
    print("\n--- [ITGC] Auditing IAM Access Control Policies ---")
    violations = 0
    for policy in policies:
        print(f"Checking policy: {policy['policy_name']}...")
        if policy["resource"] == "*" and policy["privilege_level"] == "Full":
            print(f"  [!] DEFICIENCY FOUND: Policy '{policy['policy_name']}' grants wildcard (*) full administrative privileges.")
            violations += 1
    return violations

def generate_compliance_report():
    print("==================================================")
    print("      AWS CLOUD INFRASTRUCTURE COMPLIANCE SCAN    ")
    print("      Frameworks: CIS Benchmarks / NIST SP 800-53 ")
    print("==================================================\n")
    
    s3_issues = audit_s3_buckets(mock_cloud_infrastructure["storage_buckets"])
    iam_issues = audit_iam_policies(mock_cloud_infrastructure["iam_policies"])
    
    total_issues = s3_issues + iam_issues
    print("\n==================================================")
    print(f"Audit Complete. Total Compliance Exceptions: {total_issues}")
    if total_issues > 0:
        print("Status: FAILED - Remediation required prior to audit sign-off.")
    else:
        print("Status: PASSED - Controls operating effectively.")
    print("==================================================")

if __name__ == "__main__":
    generate_compliance_report()
