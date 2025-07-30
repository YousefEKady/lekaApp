# Leka-App: Dark Web Monitoring

Leka-App is a project designed to collect leaked credential files (text files), parse and extract login data from them, and upload the results to **Elasticsearch** for easy searching and filtering via Kibana.

---
## Features

- **Data extraction** (URL - USER - PASS) from multiple file formats:
  - Key-Value format (`URL: ...`, `USER: ...`, `PASS: ...`)
  - Colon format (e.g., `https://site.com:user:pass`)
- **Generates unique JSON files** for each leaked file to avoid duplicate names.
- **Automatic upload to Elasticsearch** (choose to upload a single file or a full folder).
- **Integration with Kibana** for fast searching and filtering.
- **Step-by-step script execution** (Parsing → Uploading → Cleanup) with user prompts.

---
## Requirements

- Python 3.10+
- Docker & Docker Compose
- Python libraries from `requirements.txt`

---

## Setup

### Clone the repository

```bash
git clone https://github.com/YousefEKady/leak-app.git
```

```bash
cd leka-app
```

### Create a `.env` file

```
# Elasticsearch
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_INDEX=leaks

# Telegram API (get your own at https://my.telegram.org)
TELEGRAM_API_ID=YOUR_API_ID
TELEGRAM_API_HASH=YOUR_API_HASH
TELEGRAM_CHANNEL_ID=-100XXXXXXXXX
TELEGRAM_DOWNLOAD_ROOT=downloads
```

### Start Elasticsearch and Kibana

```
docker-compose up -d
```

--- 

## Usage

### Parsing leaked files

- Place your leaked `.txt` files inside the `downloads/` directory.

```bash
python -m src.parser.leak_parser
```

- This will create parsed `.json` files in `parsed_leaked_json/`.

### Uploading data to Elasticsearch

- Upload all JSON files in the folder

```bash
python -m src.elasticsearch.upload_leaks_to_es
```

- upload a single file

```bash
python -m src.elasticsearch.upload_leaks_to_es parsed_leaked_json/your_file.json
```

- Run full script (Parse → Upload → Cleanup)

```bash
python run_parse_and_upload.py
```
The script will ask you whether to run each step (yes/no).