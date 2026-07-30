import io
import json
from minio import Minio
from depwatch import config

class miniIO():
  def __init__(self):
    settings = config.minio_settings()
    self.client = Minio(settings['endpoint'],settings['access_key'],settings['secret_key'],secure=False)
    self.bucket = settings['bucket']

  def ensure_bucket(self):
    if not self.client.bucket_exists(self.bucket):
      self.client.make_bucket(self.bucket)

  def insertJSON(self,key,obj):
    raw = json.dumps(obj).encode("utf-8")
    data_stream = io.BytesIO(raw)
    self.client.put_object(
    self.bucket,
    key,
    data_stream,
    len(raw),
    content_type="application/json",
)
