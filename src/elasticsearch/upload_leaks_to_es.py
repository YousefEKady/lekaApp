import os
import json
from src.elasticsearch.es import es
from elasticsearch import NotFoundError
import hashlib

def should_upload(leak):
    return bool(leak.get('USER')) and bool(leak.get('PASS')) and bool(leak.get('URL'))

def make_doc_id(leak):
    # Create a unique ID based on USER+PASS+URL
    base = leak['USER'] + leak['PASS'] + leak['URL']
    return hashlib.sha256(base.encode('utf-8')).hexdigest()

def process_file(file_path, index_name='leaks'):
    """Uploads leaks from a single JSON file."""
    count = 0
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            leaks = json.load(f)
            if isinstance(leaks, dict):
                leaks = [leaks]
        except json.JSONDecodeError:
            print(f"Failed to decode {file_path}")
            return 0

        for leak in leaks:
            if should_upload(leak):
                doc_id = make_doc_id(leak)
                try:
                    es.get(index=index_name, id=doc_id)
                    continue  # Already exists
                except NotFoundError:
                    es.index(index=index_name, id=doc_id, document=leak)
                    count += 1
    return count

def upload_leaks(path, index_name='leaks'):
    total_uploaded = 0

    if os.path.isfile(path):
        # If it's a single file
        total_uploaded += process_file(path, index_name)
    elif os.path.isdir(path):
        # If it's a directory
        for filename in os.listdir(path):
            if filename.endswith('.json'):
                file_path = os.path.join(path, filename)
                total_uploaded += process_file(file_path, index_name)
    else:
        print("Invalid path. Please provide a valid file or directory.")
        return

    print(f" Uploaded {total_uploaded} leaks to Elasticsearch index '{index_name}'.")

if __name__ == '__main__':
    # Change the path here to either a single JSON file or a folder
    upload_leaks('parsed_leaked_json')
