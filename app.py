import streamlit as st
from google.cloud import storage
import uuid
import os
import bucket

# Cache the GCS client
@st.cache_resource
def get_gcs_client():
    credentials = st.secrets["gcp_service_account"]
    return storage.Client.from_service_account_info(credentials)

# Initialize GCS client and bucket name
client = get_gcs_client()
bucket_name = st.secrets["app_data"]["bucket_name"]

st.title("Image Upload and View")

# Image upload section
uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "png", "jpeg"])
if uploaded_file is not None:
    # Generate a unique filename
    file_extension = os.path.splitext(uploaded_file.name)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    # Upload to GCS and get the public URL
    public_url = bucket.upload_image(client, bucket_name, uploaded_file, unique_filename)
    # Add the URL to the list
    bucket.add_image_url(client, bucket_name, public_url)
    st.success("Image uploaded successfully!")

# Image viewing section
st.subheader("Uploaded Images")
image_urls = bucket.get_image_urls(client, bucket_name)
if image_urls:
    for url in image_urls:
        st.image(url)
else:
    st.info("No images uploaded yet.")