import subprocess
import os
import glob
from concurrent.futures import ThreadPoolExecutor

def run_parser():
    print("Parsing leaks...")
    subprocess.run(["python", "-m", "src.parser.leak_parser"], check=True)

def upload_to_mongo():
    print("Uploading leaks to MongoDB...")
    subprocess.run(["python", "-m", "src.db.upload_leaks"], check=True)

def upload_to_elasticsearch():
    print("Uploading leaks to Elasticsearch...")
    subprocess.run(["python", "-m", "src.elasticsearch.upload_leaks_to_es"], check=True)

def cleanup_json_files():
    print("Cleaning up JSON files...")
    json_dir = "parsed_leaked_json"
    if os.path.exists(json_dir):
        json_files = glob.glob(os.path.join(json_dir, "*.json"))
        deleted_count = 0
        for json_file in json_files:
            try:
                os.remove(json_file)
                deleted_count += 1
            except Exception as e:
                print(f"Failed to delete {json_file}: {e}")
        print(f"Deleted {deleted_count} JSON files from '{json_dir}'.")
    else:
        print(f"Directory '{json_dir}' does not exist.")

def ask_user(question):
    """Helper function to prompt user for yes/no and return True/False"""
    while True:
        user_input = input(f"{question} (yes/no): ").strip().lower()
        if user_input in ["yes", "y"]:
            return True
        elif user_input in ["no", "n"]:
            return False
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

def main():
    try:
        if ask_user("Run parser?"):
            run_parser()
        else:
            print("Skipping parser step.")

        if ask_user("Upload to MongoDB?"):
            upload_to_mongo()
        else:
            print("Skipping MongoDB upload.")

        if ask_user("Upload to Elasticsearch?"):
            upload_to_elasticsearch()
        else:
            print("Skipping Elasticsearch upload.")

        if ask_user("Clean up JSON files after upload?"):
            cleanup_json_files()
        else:
            print("Skipping cleanup.")

        print("All steps completed (based on your choices).")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    main()
