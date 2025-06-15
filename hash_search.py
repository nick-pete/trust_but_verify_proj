import os
import json

hash_source_file = "hash_list.json"
stix_folder = "./stix_output_gpt_hash"
summary_output_file = "hash_match_summary_gpt.json"

# Step 1: Extract list of hashes from the original input file
def extract_hash_list(input_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    return [entry["md5_hash"] for entry in data.get("data", []) if "md5_hash" in entry]

# Step 2: Check hashes in a single STIX file
def find_hashes_in_stix(hash_list, stix_file_path):
    with open(stix_file_path, 'r') as f:
        try:
            stix_data = json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️ Could not parse JSON in {stix_file_path}")
            return 0

    found_hashes = set()
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            for hash in hash_list:
                if hash in pattern:
                    found_hashes.add(hash)

    return len(found_hashes)

# Step 3: Process all STIX files in a directory
def evaluate_stix_directory(hash_list, stix_dir, output_file):
    results = []
    total_hashes = len(hash_list)

    for filename in os.listdir(stix_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(stix_dir, filename)
            match_hashes = set()

            # Get matched hashes
            with open(filepath, 'r') as f:
                try:
                    stix_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"⚠️ Could not parse JSON in {filepath}")
                    continue

            unexpected_patterns = []
            seen_patterns = set()
            duplicate_patterns = []
            
            for obj in stix_data.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")

                    # check for duplicates
                    if pattern in seen_patterns:
                        print(f"♻️ Duplicate pattern in {filename}: {pattern}")
                        duplicate_patterns.append(pattern)
                    else:
                        seen_patterns.add(pattern)

                    found = False
                    for h in hash_list:
                        if h in pattern:
                            match_hashes.add(h)
                            found = True
                            break

                    if not found:
                        print(f"⚠️ Unexpected pattern in {filename}: {pattern}")
                        unexpected_patterns.append(pattern)

            match_count = len(match_hashes)
            missed_hashes = list(set(hash_list) - match_hashes)

            percentage = (match_count / total_hashes) * 100 if total_hashes else 0

            results.append({
                "file": filename,
                "matched_hashes": match_count,
                "total_hashes": total_hashes,
                "percentage": round(percentage, 2),
                "missing_hashes": missed_hashes,
                "extra_patterns": unexpected_patterns,
                "duplicate_patterns": duplicate_patterns 
            })

            print(f"✅ {filename}: {match_count}/{total_hashes} Hashes matched ({round(percentage, 2)}%)")
            if missed_hashes:
                print(f"❌ Missing {len(missed_hashes)} hashes in {filename}:")
                for missing in missed_hashes:
                    print(f"  - {missing}")

    # Save summary results
    with open(output_file, 'w') as out:
        json.dump(results, out, indent=2)
    print(f"\n📄 Saved summary with missing hashes to {output_file}")


    # Save summary results
    with open(output_file, 'w') as out:
        json.dump(results, out, indent=2)
    print(f"\n📄 Saved summary to {output_file}")

hash_list = extract_hash_list(hash_source_file)
evaluate_stix_directory(hash_list, stix_folder, summary_output_file)