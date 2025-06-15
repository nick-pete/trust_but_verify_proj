import os
import json
from stix2validator import validate_file, print_results

stix_folder = [YOUR_FOLDER_TO_SCAN]
summary_output_file = "stix_validation_gpt_url.json"

def evaluate_stix_directory(stix_dir, output_file):
    val_res = []

    for filename in os.listdir(stix_dir):
        if filename.endswith(".json"):
            print(f"Validating {filename}...")
            filepath = os.path.join(stix_dir, filename)
            try:
                results = validate_file(filepath)
                summary = {
                    "file": filename,
                    "is_valid": results.is_valid
                }
                val_res.append(summary)

            except Exception as e:
                print(f"❌ Error validating {filename}: {e}")
            

    # Save summary results
    with open(output_file, 'w') as out:
        json.dump(val_res, out, indent=2)
    print(f"\n📄 Saved summary to {output_file}")

evaluate_stix_directory(stix_folder, summary_output_file)