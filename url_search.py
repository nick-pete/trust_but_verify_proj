import os
import json

url_source_file = [YOUR_SOURCE_FILE]
stix_folder = [YOUR_FOLDER_TO_SCAN]
summary_output_file = "url_match_summary_gpt.json"

# Step 1: Extract list of urls from the original input file
def extract_url_list(input_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    return [entry["url"] for entry in data.get("urls", []) if "url" in entry]

# Step 2: Check urls in a single STIX file
def find_urls_in_stix(url_list, stix_file_path):
    with open(stix_file_path, 'r') as f:
        try:
            stix_data = json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️ Could not parse JSON in {stix_file_path}")
            return 0

    found_urls = set()
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            for url in url_list:
                if url in pattern:
                    found_urls.add(url)

    return len(found_urls)

# Step 3: Process all STIX files in a directory
def evaluate_stix_directory(url_list, stix_dir, output_file):
    results = []
    total_urls = len(url_list)
    url_set = set(url_list)

    for filename in os.listdir(stix_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(stix_dir, filename)
            url_occurrences = {url: 0 for url in url_list}
            unexpected_patterns = set()  # ✅ Collect unexpected pattern strings

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
                    for u in url_list:
                        if u in pattern:
                            url_occurrences[u] += 1
                            matched = True
                    if not matched:
                        # ✅ Just save the whole pattern
                        unexpected_patterns.add(pattern.strip())

            matched_count = sum(1 for count in url_occurrences.values() if count > 0)
            percentage = (matched_count / total_urls) * 100 if total_urls else 0

            repeated_urls = [url for url, count in url_occurrences.items() if count > 1]
            omitted_urls = [url for url, count in url_occurrences.items() if count == 0]

            results.append({
                "file": filename,
                "matched_urls": matched_count,
                "total_urls": total_urls,
                "percentage": round(percentage, 2),
                "repeated_urls": repeated_urls,
                "omitted_urls": omitted_urls,
                "unexpected_patterns": sorted(unexpected_patterns)  # ✅ Whole patterns
            })

            print(f"\n📄 {filename}: {matched_count}/{total_urls} matched ({round(percentage, 2)}%)")
            if repeated_urls:
                print(f"♻️ Repeated ({len(repeated_urls)}):")
                for url in repeated_urls:
                    print(f"  - {url} (count: {url_occurrences[url]})")
            if omitted_urls:
                print(f"❌ Omitted ({len(omitted_urls)}):")
                for url in omitted_urls:
                    print(f"  - {url}")
            if unexpected_patterns:
                print(f"❓ Unexpected patterns ({len(unexpected_patterns)}):")
                for pattern in sorted(unexpected_patterns):
                    print(f"  - {pattern}")

    with open(output_file, 'w') as out:
        json.dump(results, out, indent=2)
    print(f"\n✅ Saved summary to {output_file}")


url_list = extract_url_list(url_source_file)
evaluate_stix_directory(url_list, stix_folder, summary_output_file)