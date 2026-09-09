import io
import json
import zipfile

import requests

ECOSYSTEM = "PyPI"
url = f"https://storage.googleapis.com/osv-vulnerabilities/{ECOSYSTEM}/all.zip"


reponse = requests.get(url)
z = zipfile.ZipFile(io.BytesIO(reponse.content))

for filename in z.namelist():
    # print(filename)
    with z.open(filename) as file:
        record = json.load(file)
        # print(record)

for key, item in record.items():
    print(f"{key}:              {item}")
