import streamlit as st
import uuid
import os
from google.cloud import storage
import bucket
import stego

# Cache the GCS client for performance
@st.cache_resource
def get_gcs_client():
    credentials = st.secrets["gcp_service_account"]
    return storage.Client.from_service_account_info(credentials)

client = get_gcs_client()
bucket_name = st.secrets["app_data"]["bucket_name"]

# Sidebar for authentication
with st.sidebar:
    st.title("Image Steganography")
    st.markdown('##')   # add empty space
    with st.container(border=True):
        if st.experimental_user.is_logged_in:
            pad1, col, pad2 = st.columns([1,3,1])
            with col:
                st.write(f"**{st.experimental_user.name}**")
                if st.button("Logout", use_container_width=True):
                    st.logout()
        else:
            pad1, col, pad2 = st.columns([1,5,1])
            with col:
                st.write("Anyone can view uploaded images.")
                st.write("Login to create and upload images using Steganography.")
                if st.button("Login with Google", use_container_width=True):
                    st.login("google")
    st.markdown('######')   # add empty space
    st.write("If you need to Reset the app, click the dots ( **⋮** ) in the top-right and select ReRun.")

# Initialize session state for selected image
if "selected" not in st.session_state:
    st.session_state.selected = None

# If user logged in then show Upload
if st.experimental_user.is_logged_in:
    tab1, tab2 = st.tabs(["**Insert Message**", "**Extract Message**"])

    with tab1:
        st.markdown('######')   # add empty space
        st.markdown("#### Step 1: Upload a PNG file as a Carrier")
        with st.container(border=True):
            uploaded_file = st.file_uploader("Upload a PNG", type=["png"], label_visibility="collapsed")
        if uploaded_file is not None:
            st.markdown('######')   # add empty space
            st.markdown("#### Step 2: Add a Message to insert and set S, C")
            with st.form("insert_form", clear_on_submit=True, enter_to_submit=False):
                M = st.text_input("Message (M)", placeholder="string")
                col1, col2 = st.columns(2)
                with col1:
                    S = st.text_input("Start bit (S)", placeholder="int")
                with col2:
                    C = st.text_input("Mode (C)", placeholder="int")
                pad1, col, pad2 = st.columns([1,1,1])
                with col:
                    submit = st.form_submit_button("Create", use_container_width=True)
                if submit:
                    modified_img = stego.embed_in_png(uploaded_file, M.encode(), int(S), int(C))
                    st.success("Message embedded successfully!")

                    file_extension = os.path.splitext(uploaded_file.name)[1]
                    unique_filename = f"{uuid.uuid4()}_{len(M.encode())}_{int(S)}_{int(C)}_{file_extension}"
                    public_url = bucket.upload_image(client, bucket_name, modified_img, unique_filename)
                    bucket.add_image_url(client, bucket_name, public_url)
                    st.success("Image uploaded successfully!")

    with tab2:
        st.markdown('######')   # add empty space
        st.markdown("#### Select an Image, optionally change parameters, and Extract")
        with st.form("extract_form"):
            if st.session_state.selected is not None:
                Sp = st.session_state.selected.split("_")[2]
                Cp = st.session_state.selected.split("_")[3]
                Mp = st.session_state.selected.split("_")[1]
            else:
                Sp, Cp, Mp = 0, 0, 0
            col1, col2, col3 = st.columns(3)
            with col1:
                S = st.text_input("Start bit (S)", value=Sp)
            with col2:
                C = st.text_input("Mode (C)", value=Cp)
            with col3:
                M_len = st.text_input("Message Length (in Bytes)", value=Mp)
            pad1, col, pad2 = st.columns([1,1,1])
            with col:
                submit = st.form_submit_button("Extract", use_container_width=True)
            if submit:
                if st.session_state.selected:
                    image_bytes = bucket.download_image(client, bucket_name, st.session_state.selected)
                    msg = stego.extract_from_png(image_bytes, int(S), int(C), int(M_len) * 8)
                    try:
                        st.success(f"Message: {msg.decode('utf-8')}")
                    except UnicodeDecodeError:
                        st.error(f"Extraction failed or message is not UTF-8: {msg}")
                else:
                    st.warning("Please select an image first!")

        st.markdown('######')   # add empty space
        image_urls = bucket.get_image_urls(client, bucket_name)
        with st.container(border=True):
            if image_urls:
                col1, col2, col3 = st.columns(3)
                for i, url in enumerate(image_urls):
                    if i % 3 == 0:
                        col1.image(url)
                        if col1.button(f"Select", key=i, use_container_width=True):
                            st.session_state.selected = url
                            st.rerun()
                    elif i % 3 == 1:
                        col2.image(url)
                        if col2.button(f"Select", key=i, use_container_width=True):
                            st.session_state.selected = url
                            st.rerun()
                    elif i % 3 == 2:
                        col3.image(url)
                        if col3.button(f"Select", key=i, use_container_width=True):
                            st.session_state.selected = url
                            st.rerun()
            else:
                st.info("No images uploaded yet.")


# Display images (accessible to everyone)
if st.experimental_user.is_logged_in is False:
    image_urls = bucket.get_image_urls(client, bucket_name)
    if image_urls:
        col1, col2, col3 = st.columns(3)
        for i, url in enumerate(image_urls):
            if i % 3 == 0: col1.image(url)
            elif i % 3 == 1: col2.image(url)
            elif i % 3 == 2: col3.image(url)
    else:
        st.info("No images uploaded yet.")