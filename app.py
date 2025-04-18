# 3rd party lib
import streamlit as st
from google.cloud import storage
# std lib
import os, base64
# app lib
from lib import bucket
from lib import crypto

# Init global GCS client and cache for performance
@st.cache_resource
def get_gcs_client():
    credentials = st.secrets["gcp_service_account"]
    return storage.Client.from_service_account_info(credentials)
client = get_gcs_client()

# Init app-level session state
# (is Server-Side for non-widget states AKA app-level is Secure)
# https://discuss.streamlit.io/t/hey-i-have-a-serious-issue-about-storing-things-in-the-session-state/35761/6
if "bucket_name" not in st.session_state:
    st.session_state.bucket_name = st.secrets["app_data"]["bucket_name"]
if "master_key" not in st.session_state:
    st.session_state.master_key = None
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = None

# Actions for Login and Logout pages
def login():
    st.write("*Login to use Steganographic and Cryptographic services.*")
    with st.sidebar:
        st.write("Not Signed In:")
        if st.button("Login with Google", use_container_width=True, type="primary"):
            st.login("google")

    # Display images (accessible to everyone)
    image_urls = bucket.get_image_urls(client, st.session_state.bucket_name)
    if image_urls:
        col1, col2, col3 = st.columns(3)
        for i, url in enumerate(image_urls):
            if i % 3 == 0: col1.image(url)
            elif i % 3 == 1: col2.image(url)
            elif i % 3 == 2: col3.image(url)
    else:
        st.info("No images uploaded yet.")

def logout():
    st.session_state.clear()
    st.logout()

# Setup each page
if st.experimental_user.is_logged_in:
    login_name = f" ({st.experimental_user.name})"
else:
    login_name = ""
login_page = st.Page(login, title="Login", icon=":material/login:")
logout_page = st.Page(logout, title=f"Logout{login_name}", icon=":material/logout:")
settings_page = st.Page("pages/settings_page.py", title="Settings", icon=":material/settings:")
stego_page = st.Page("pages/services/stego_page.py", title="Image Steganography", icon=":material/photo_library:", default=st.experimental_user.is_logged_in)
crypto_page = st.Page("pages/services/crypto_page.py", title="Cryptography", icon=":material/lock:")

# Setup page groups
account_pages = [logout_page, settings_page]
services_pages = [stego_page, crypto_page]

# Common for all pages
st.title("Steganography and Cryptography")

if st.experimental_user.is_logged_in:
    # just after login, we finish setting up user acct
    st.session_state.master_key = base64.b64decode(st.secrets["app_data"]["master_key"])
    sub = st.experimental_user.sub
    users_data = bucket.get_users_data(client, st.session_state.bucket_name)
    
    if sub not in users_data:
        # Register new user
        user_key = os.urandom(32)  # Generate random 256-bit key
        encrypted_user_key = crypto.encrypt_user_key(st.session_state.master_key, user_key)
        users_data[sub] = {
            "encrypted_user_key": base64.b64encode(encrypted_user_key).decode('utf-8')
        }
        bucket.update_users_data(client, st.session_state.bucket_name, users_data)
        bucket.create_user_folder(client, st.session_state.bucket_name, sub)
        st.toast("User registered successfully!", icon=":material/done_outline:")
    else:
        # Retrieve and decrypt the user key
        encrypted_user_key = base64.b64decode(users_data[sub]['encrypted_user_key'])
        user_key = crypto.decrypt_user_key(st.session_state.master_key, encrypted_user_key)
        st.session_state.encryption_key = user_key

    # navigate to user pages
    pg = st.navigation({"Account": account_pages, "Services": services_pages}, expanded=True)

    # apply after navigation to put below nav bar
    with st.sidebar:
        st.markdown('######')   # add empty space
        st.write("Site Tips:")
        st.write("If you need to Reset the app, click the dots ( **⋮** ) in the top-right and select ReRun.")
        st.divider()            # horizontal rule
else:
    # navigate to landing page
    pg = st.navigation([login], expanded=True)

pg.run()