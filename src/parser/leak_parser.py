import os
import re
import json
import hashlib
from tqdm import tqdm

def clean_url(url: str) -> str:
    """Normalize URL to avoid //// and extra chars."""
    url = url.strip().replace("(", "").replace(")", "")
    url = re.sub(r'\/{3,}', '//', url)  # replace multiple slashes
    if not url.startswith("http"):
        url = "https://" + url
    return url

def is_probable_domain(text: str) -> bool:
    """Check if text looks like a domain or path."""
    return bool(re.search(r'\w+\.\w+', text))

def parse_colon_format(line: str):
    """Handles generic colon-separated format: url:user:pass"""
    parts = [p.strip() for p in line.split(":") if p.strip()]
    if len(parts) < 3:
        return None

    # Special case: line starts with "https" but next part is domain
    if parts[0].lower() in ["http", "https"] and is_probable_domain(parts[1]):
        url = clean_url(parts[0] + "://" + parts[1])
        rest = parts[2:]
        if len(rest) != 2:
            return None
        return {"URL": url, "USER": rest[0], "PASS": rest[1]}

    # Find which part is URL
    url_idx = -1
    for i, part in enumerate(parts):
        if part.startswith("http") or is_probable_domain(part):
            url_idx = i
            break
    if url_idx == -1:
        return None

    url = clean_url(parts[url_idx])
    rest = parts[:url_idx] + parts[url_idx+1:]
    if len(rest) != 2:
        return None

    return {"URL": url, "USER": rest[0], "PASS": rest[1]}

def parse_file(file_path: str):
    """Parse a file supporting both key-value (multi-line) and colon format."""
    parsed_data = []
    buffer = {"URL": None, "USER": None, "PASS": None}

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Detect key-value style
            kv_match = re.match(r'^(URL|USER|PASS)\s*:\s*(.+)$', line, flags=re.IGNORECASE)
            if kv_match:
                key = kv_match.group(1).upper()
                value = kv_match.group(2).strip()
                if key == "URL":
                    value = clean_url(value)
                buffer[key] = value

                # If all three keys found → save and reset
                if all(buffer.values()):
                    parsed_data.append({
                        "URL": buffer["URL"],
                        "USER": buffer["USER"],
                        "PASS": buffer["PASS"],
                        "source_file": file_path
                    })
                    buffer = {"URL": None, "USER": None, "PASS": None}
                continue

            # Else try colon format
            parsed = parse_colon_format(line)
            if parsed:
                parsed["source_file"] = file_path
                parsed_data.append(parsed)

    return parsed_data

def unique_json_name(file_path: str) -> str:
    """Generate unique JSON filename based on file path hash."""
    hash_digest = hashlib.md5(file_path.encode('utf-8')).hexdigest()[:10]
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    return f"{base_name}_{hash_digest}.json"

def parse_directory(input_dir: str, output_dir: str):
    """Parse all txt files in directory and save JSON results."""
    os.makedirs(output_dir, exist_ok=True)

    for root, _, files in os.walk(input_dir):
        for file in tqdm(files, desc="Parsing files"):
            if not file.lower().endswith(".txt"):
                continue

            full_path = os.path.join(root, file)
            parsed = parse_file(full_path)

            if parsed:
                json_name = unique_json_name(full_path)
                output_file = os.path.join(output_dir, json_name)
                with open(output_file, 'w', encoding='utf-8') as out_f:
                    json.dump(parsed, out_f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    INPUT_DIR = "downloads"
    OUTPUT_DIR = "parsed_leaked_json"
    parse_directory(INPUT_DIR, OUTPUT_DIR)
    print("Parsing complete.")
