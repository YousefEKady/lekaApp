import os
from dotenv import load_dotenv

load_dotenv()

#MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
#MONGO_DB = os.getenv("MONGO_DB", "leakdb")

ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ELASTICSEARCH_PORT = int(os.getenv("ELASTICSEARCH_PORT", 9200))
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "leaks") 