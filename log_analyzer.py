# A simple script to flag IPs with multiple failed logins

log_file = "server_logs.txt"
failed_attempts = {}
threshold = 3  # Alert if failed attempts are greater than or equal to this

print("--- Analyzing Server Logs for Suspicious Activity ---")

with open(log_file, "r") as file:
    for line in file:
        if "FAILED" in line:
            # Extract the IP address (the first word in the log line)
            ip = line.split()[0]
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

# Check which IPs crossed the threshold
for ip, count in failed_attempts.items():
    if count >= threshold:
        print(f"[ALERT] Potential brute-force attack detected from IP: {ip} ({count} failed attempts)" 
