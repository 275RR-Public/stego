import json
from io import BytesIO
from urllib.parse import unquote

# Google Cloud bucket functions for Steganography
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
    """Download an image from GCS based on its public URL."""
    blob_name = unquote(url.split('/')[-1])  # Decode URL-encoded characters
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    if blob.exists():
        return BytesIO(blob.download_as_bytes())
    else:
        raise ValueError(f"Image not found in bucket: {blob_name}")


# Google Cloud bucket functions for User Management
def get_users_data(client, bucket_name):
    """Retrieve user data from users.json in GCS."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob('users.json')
    if blob.exists():
        data = json.loads(blob.download_as_string())
        return data
    else:
        return {}

def update_users_data(client, bucket_name, users_data):
    """Update users.json in GCS with new user data."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob('users.json')
    blob.upload_from_string(json.dumps(users_data))

def create_user_folder(client, bucket_name, username):
    """Create a user-specific folder in GCS."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(f'users/{username}/')
    blob.upload_from_string('')

def delete_folder(client, bucket_name, prefix):
    bucket = client.bucket(bucket_name)
    blobs = list(bucket.list_blobs(prefix=prefix))
    if blobs:
        bucket.delete_blobs(blobs)


# Generic File Operations
def upload_file(client, bucket_name, file_path, data):
    """Upload data to a specific path in GCS. Accepts bytes, strings, or file-like objects."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_path)
    if isinstance(data, (str, bytes)):
        blob.upload_from_string(data)
    else:
        blob.upload_from_file(data)
    return file_path

def delete_file(client, bucket_name, file_path):
    """Delete a file from GCS."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_path)
    blob.delete()

def download_file(client, bucket_name, file_path):
    """Download a file from a specific path in GCS as bytes."""
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_path)
    return blob.download_as_bytes()

def list_files(client, bucket_name, prefix):
    """List files in GCS with a given prefix."""
    bucket = client.bucket(bucket_name)
    blobs = bucket.list_blobs(prefix=prefix)
    return [blob.name for blob in blobs]