import json
from google.cloud import storage
from io import BytesIO

def upload_image(client, bucket_name, file, filename):
    """Upload an image to GCS and return its public URL."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(filename)
    blob.upload_from_file(file)
    blob.make_public()  # Make the image publicly accessible
    return blob.public_url

def add_image_url(client, bucket_name, url, json_filename="image_list.json"):
    """Add an image URL to a JSON file stored in GCS."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(json_filename)
    if blob.exists():
        data = json.loads(blob.download_as_string())
    else:
        data = []
    data.append(url)
    blob.upload_from_string(json.dumps(data))

def get_image_urls(client, bucket_name, json_filename="image_list.json"):
    """Retrieve the list of image URLs from the JSON file in GCS."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(json_filename)
    if blob.exists():
        data = json.loads(blob.download_as_string())
        return data
    return []

def download_image(client, bucket_name, url):
    """Download an image from GCS given its public URL and return its bytes."""
    blob_name = url.split('/')[-1]
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    if blob.exists():
        return BytesIO(blob.download_as_bytes())
    else:
        raise ValueError(f"Image not found in bucket: {blob_name}")