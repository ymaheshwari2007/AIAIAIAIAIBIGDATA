import io
import json

from minio import Minio

from depwatch import config


class miniIO:
    def __init__(self):
        settings = config.minio_settings()
        self.client = Minio(
            settings["endpoint"],
            settings["access_key"],
            settings["secret_key"],
            secure=False,
        )
        self.bucket = settings["bucket"]

    def ensure_bucket(self):
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def insertJSON(self, key, obj):
        raw = json.dumps(obj).encode("utf-8")
        data_stream = io.BytesIO(raw)
        self.client.put_object(
            self.bucket,
            key,
            data_stream,
            len(raw),
            content_type="application/json",
        )

    def readJSON(self, key):
        # mirror of insertJSON: fetch an object and parse it back to Python.
        # get_object streams over HTTP, so close + release_conn or the pooled
        # connection leaks.
        response = self.client.get_object(self.bucket, key)
        try:
            return json.loads(response.read())
        finally:
            response.close()
            response.release_conn()

    def listKeys(self, prefix):
        # object names under a prefix, e.g. a whole partition "github/dt=2026-07-27/"
        objects = self.client.list_objects(self.bucket, prefix=prefix, recursive=True)
        return [obj.object_name for obj in objects]
