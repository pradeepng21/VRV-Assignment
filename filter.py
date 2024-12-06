import re
import csv
from collections import Counter


def filter_log_file(log_file_path, output_csv_path, failed_login_threshold):

    ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    endpoint_regex = r"\"[A-Z]+ (\/[^\s]*)"
    failed_login_regex = r"(401|Invalid credentials)"


    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(log_file_path, "r") as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group()
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Detect failed logins
            if re.search(failed_login_regex, line):
                if ip_match:
                    failed_logins[ip] += 1

    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}

    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20}{count:<20}")

    # Save results to CSV
    with open(output_csv_path, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

    print(f"\nResults saved to {output_csv_path}")


if __name__ == "__main__":
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"

    threshold = 10

    filter_log_file(log_file, output_csv, threshold)

