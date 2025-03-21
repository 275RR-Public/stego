import streamlit as st
import uuid
import os
from google.cloud import storage
import bucket

# Cache the GCS client for performance
@st.cache_resource
def get_gcs_client():
    credentials = st.secrets["gcp_service_account"]
    return storage.Client.from_service_account_info(credentials)

client = get_gcs_client()
bucket_name = st.secrets["app_data"]["bucket_name"]

# Sidebar for authentication
with st.sidebar:
    st.title("Login")
    st.write("Anyone can view uploaded images.")
    if st.experimental_user.is_logged_in:
        st.write(f"Welcome, **{st.experimental_user.name}**!")
        if st.button("Logout"):
            st.logout()
    else:
        st.write("Login to create and upload images using Steganography.")
        if st.button("Login with Google"):
            st.login("google")

# If user logged in then show Upload
if st.experimental_user.is_logged_in:
    uploaded_file = st.file_uploader("Upload an image", type=["jpg", "png", "jpeg"])
    if uploaded_file is not None:
        file_extension = os.path.splitext(uploaded_file.name)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        public_url = bucket.upload_image(client, bucket_name, uploaded_file, unique_filename)
        bucket.add_image_url(client, bucket_name, public_url)
        st.success("Image uploaded successfully!")

# Display images (accessible to everyone)
st.title("Image Steganography")
image_urls = bucket.get_image_urls(client, bucket_name)
if image_urls:
    with st.container(border=True):
        col1, col2, col3 = st.columns(3)
        for i, url in enumerate(image_urls):
            if i % 3 == 0: col1.image(url)
            elif i % 3 == 1: col2.image(url)
            elif i % 3 == 2: col3.image(url)
else:
    st.info("No images uploaded yet.")