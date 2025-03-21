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

# Function to display images (accessible to everyone)
def display_images():
    image_urls = bucket.get_image_urls(client, bucket_name)
    if image_urls:
        for url in image_urls:
            st.image(url)
    else:
        st.info("No images uploaded yet.")

# Check if the user is logged in
if st.experimental_user.is_logged_in:
    st.write(f"Welcome, {st.experimental_user.name}!")
    
    # Show upload widget only to logged-in users
    uploaded_file = st.file_uploader("Upload an image", type=["jpg", "png", "jpeg"])
    if uploaded_file is not None:
        file_extension = os.path.splitext(uploaded_file.name)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        public_url = bucket.upload_image(client, bucket_name, uploaded_file, unique_filename)
        bucket.add_image_url(client, bucket_name, public_url)
        st.success("Image uploaded successfully!")
    
    # Show logout button
    if st.button("Logout"):
        st.logout()
else:
    # Show login button and message for non-logged-in users
    if st.button("Login with Google"):
        st.login("google")
    st.write("Please log in to upload images.")

# Always display images, regardless of login status
display_images()