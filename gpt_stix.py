import json
import uuid
import re
import os
import time
from datetime import datetime
from openai import OpenAI
from typing import List, Optional, Literal
from pydantic import RootModel, BaseModel, Field

# define schema

class Indicator(BaseModel):
    type: Literal["indicator"] = Field(..., description="Must be the literal 'indicator'")
    spec_version: Literal["2.0", "2.1"] = Field(..., description="STIX specification version")
    id: str = Field(..., description="STIX ID, leave blank in output")
    created: str = Field(..., description="ISO 8601 timestamp, leave blank")
    modified: str = Field(..., description="ISO 8601 timestamp, leave blank")
    pattern: str = Field(..., description="Detection pattern (e.g., '[ipv4-addr:value = '1.1.1.1']')")
    pattern_type: str = Field(..., description="Pattern type (e.g., 'stix', 'yara')")
    valid_from: str = Field(..., description="Start time from which the indicator is valid (ISO 8601)")
    description: Optional[str] = Field(None, description="Contextual description of the indicator")

    class Config:
        title = "STIX 2.1 Indicator (Required Fields Only, GPT-Compatible)"

class IndicatorListWrapper(BaseModel):
    items: list[Indicator]


# Helper: Extract first valid JSON object or array
def extract_first_json_block(text):
    """
    Attempts to extract the first full JSON object or array from a string.
    """
    brace_stack = []
    start = None

    for i, char in enumerate(text):
        if char == '{' or char == '[':
            if not brace_stack:
                start = i
            brace_stack.append(char)
        elif char == '}' or char == ']':
            if brace_stack:
                brace_stack.pop()
                if not brace_stack and start is not None:
                    return text[start:i+1]
    return None


# Function to split list into chunks
def batch_list(items, batch_size):
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]

# Add unique ID, date created, and date modified
def append_fields(stix_bundle):
    now = datetime.utcnow()
    timestamp_with_ms = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    for object in stix_bundle["objects"]:
        object["id"] = f"indicator--{uuid.uuid4()}"
        object["created"] = timestamp_with_ms
        object["modified"] = timestamp_with_ms
        object["valid_from"] = timestamp_with_ms
    return stix_bundle

def extract_list_payload(obj):
    """Returns the first list found in the top-level keys of a dict, or the object itself if it's a list."""
    if isinstance(obj, list):
        return obj
    elif isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, list):
                return v
    return [] 

# Function to send one batch to ChatGPT
def generate_stix_for_batch(client, batch, batch_number):
    prompt = json.dumps({"data": batch}, indent=2)
    
    response = client.beta.chat.completions.parse(
        model="gpt-4o",
        messages=[
            {
                "role": "system", 
                "content": """
                    You are a system that converts indicators of compromise (IOCs) from raw threat intelligence into STIX 2.1 Indicator objects.

                    Each input item may represent a URL, domain, IP address (IPv4 or IPv6), file hash (MD5, SHA1, SHA256), or other observable.

                    For each item:
                    - Use the appropriate STIX pattern (e.g., `[url:value = '...']`, `[domain-name:value = '...']`, `[file:hashes.SHA256 = '...']`, `[ipv4-addr:value = '...']`)
                    - Include a basic name and a short description if available
                    - Leave `id`, `created`, `modified`, and `valid_from` fields blank
                    - Generate exactly one STIX indicator. Process all items without omission, skipping none.
                    
                    Output a **JSON array** of STIX Indicator objects — do not wrap in a bundle, dictionary, or markdown

                    Wrap the array of indicators inside a JSON object with key items.

                    """
            },
            {"role": "user", "content": prompt}
        ],
        response_format=IndicatorListWrapper
    )
    
    try:
        content = response.choices[0].message.content
    except (AttributeError, IndexError) as e:
        print(f"Error extracting content for batch {batch_number}: {e}")
        print(f"Response details: {response}")  # Full response for debug
        return None  # or raise an Exception

    print(f"✅ Processed batch {batch_number}")
    return content

# Main function
def convert_to_stix_via_chatgpt(input_file, output_file, api_key, batch_size=25):
    with open(input_file, 'r') as f:
        full_input = json.load(f)

    data = extract_list_payload(full_input)
    client = OpenAI(api_key=api_key)

    all_indicators = []

    for batch_num, batch in enumerate(batch_list(data, batch_size), start=1):
        stix_text = generate_stix_for_batch(client, batch, batch_num)
        json_text = json.loads(stix_text)

        try:
            parsed = json_text["items"]
            
            if not isinstance(parsed, list):
                raise ValueError("Expected top-level JSON array of indicator objects.")
            
            all_indicators.extend(parsed)

        except Exception as e:
            print(f"⚠️ Failed to parse batch {batch_num}: {e}")
            with open(f"failed_batch_{batch_num}.txt", "w") as err_file:
                err_file.write(stix_text)
            print(f"📝 Saved raw response to failed_batch_{batch_num}.txt")

    # Build the final STIX bundle
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": all_indicators
    }
    append_fields(stix_bundle)

    with open(output_file, 'w') as f:
        json.dump(stix_bundle, f, indent=2)

    print(f"Saved {len(all_indicators)} indicators to {output_file}")


# Define input and output file
input_file = [INPUT_FILENAME] #Replace with your input file
api_key = [YOUR_API_KEY] # Replace with your API Key

for i in range(1, 2):
    filename = f"stix_output_{i:03}.json"
    output_dir = [YOUR_OUTPUT_DIR]
    output_file = os.path.join(output_dir, filename)
    convert_to_stix_via_chatgpt(input_file, output_file, api_key)
    time.sleep(1)
