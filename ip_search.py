import os
import json

ip_source_file = [YOUR_SOURCE_FILE]
stix_folder = [YOUR_FOLDER_TO_SCAN]
summary_output_file = "ip_match_summary_gpt.json"

# Step 1: Extract list of IPs from the original input file
def extract_ip_list(input_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    return [entry["ipAddress"] for entry in data.get("data", []) if "ipAddress" in entry]

# Step 2: Check IPs in a single STIX file
def find_ips_in_stix(ip_list, stix_file_path):
    with open(stix_file_path, 'r') as f:
        try:
            stix_data = json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️ Could not parse JSON in {stix_file_path}")
            return 0

    found_ips = set()
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            for ip in ip_list:
                if ip in pattern:
                    found_ips.add(ip)

    return len(found_ips)

# Step 3: Process all STIX files in a directory
def evaluate_stix_directory(ip_list, stix_dir, output_file):
    results = []
    total_ips = len(ip_list)
    ip_set = set(ip_list)

    for filename in os.listdir(stix_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(stix_dir, filename)
            ip_occurrences = {ip: 0 for ip in ip_list}
            unexpected_patterns = set()

            with open(filepath, 'r') as f:
                try:
                    stix_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"⚠️ Could not parse JSON in {filepath}")
                    continue

            for obj in stix_data.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    matched = False
                    for ip in ip_list:
                        if ip in pattern:
                            ip_occurrences[ip] += 1
                            matched = True
                    if not matched:
                        unexpected_patterns.add(pattern.strip())

            matched_count = sum(1 for count in ip_occurrences.values() if count > 0)
            percentage = (matched_count / total_ips) * 100 if total_ips else 0

            repeated_ips = [ip for ip, count in ip_occurrences.items() if count > 1]
            omitted_ips = [ip for ip, count in ip_occurrences.items() if count == 0]

            results.append({
                "file": filename,
                "matched_ips": matched_count,
                "total_ips": total_ips,
                "percentage": round(percentage, 2),
                "repeated_ips": repeated_ips,
                "omitted_ips": omitted_ips,
                "unexpected_patterns": sorted(unexpected_patterns)
            })

            print(f"\n📄 {filename}: {matched_count}/{total_ips} IPs matched ({round(percentage, 2)}%)")
            if repeated_ips:
                print(f"♻️ Repeated ({len(repeated_ips)}):")
                for ip in repeated_ips:
                    print(f"  - {ip} (count: {ip_occurrences[ip]})")
            if omitted_ips:
                print(f"❌ Omitted ({len(omitted_ips)}):")
                for ip in omitted_ips:
                    print(f"  - {ip}")
            if unexpected_patterns:
                print(f"❓ Unexpected patterns ({len(unexpected_patterns)}):")
                for pattern in sorted(unexpected_patterns):
                    print(f"  - {pattern}")

    with open(output_file, 'w') as out:
        json.dump(results, out, indent=2)
    print(f"\n✅ Saved summary to {output_file}")


ip_list = extract_ip_list(ip_source_file)
evaluate_stix_directory(ip_list, stix_folder, summary_output_file)