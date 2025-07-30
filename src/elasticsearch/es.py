from elasticsearch import Elasticsearch
from src.config.config import ELASTICSEARCH_HOST, ELASTICSEARCH_PORT

es = Elasticsearch(f"http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}") 