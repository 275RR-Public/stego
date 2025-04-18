# 3rd party lib
import streamlit as st
from urllib.parse import unquote
# std lib
import os, uuid, re
# app lib
from app import get_gcs_client
import lib.bucket as bucket
import lib.stego as stego

# Init GCS client
client = get_gcs_client()

# Init page-level session state for selected image
if "selected" not in st.session_state:
    st.session_state.selected = None

with st.sidebar:
    st.write("Steganography Tips:")
    st.write("1. Insert a message. The start bit (S) controls where to begin embedding,"
    " and the mode (C) controls the step between changes. To minimize visual impact,"
    " especially in solid-color images, modify the least significant bits (LSBs)."
    " For example, set S=7 and C=8 to change the LSB of each byte, which is less noticeable than S=0"
    " (most significant bit).")
    st.write("2. Extract a message. Once you insert a message into a PNG,"
    " you can extract it by providing the correct S, C, and length variables."
    " These are automatically populated for convenience.")
    st.write("3. The first few images in **Extract Message** have been added as examples.")

st.header(":material/photo_library: Image Steganography")
tab1, tab2 = st.tabs(["**1. Insert Message**", "**2. Extract Message**"])

with tab1:
    st.markdown('######')   # add empty space
    st.markdown("#### Step 1a: Upload a PNG file as a Carrier")
    with st.container(border=True):
        uploaded_file = st.file_uploader("Upload a PNG", type=["png"], label_visibility="collapsed")
    if uploaded_file is not None:
        st.markdown('######')   # add empty space
        st.markdown("#### Step 1b: Add a Message to insert and set S, C")
        with st.form("insert_form", clear_on_submit=True, enter_to_submit=False):
            M = st.text_input("Message (M)", placeholder="string (A-Z, a-z, 0-9, space, !, comma, period only)")
            col1, col2 = st.columns(2)
            with col1:
                S = st.text_input("Start bit (S)", placeholder="non-negative int")
            with col2:
                C = st.text_input("Mode (C)", placeholder="positive int or list of int (eg 8 or 8,16,24)")
            pad1, col, pad2 = st.columns([1,1,1])
            with col:
                submit = st.form_submit_button("Create", use_container_width=True)
            if submit:
                try:
                    if not re.match(r'^[A-Za-z0-9,!. ]*$', M):
                        raise ValueError("Message can only contain A-Z, a-z, 0-9, space, !, comma, period")
                    if not M.strip():
                        raise ValueError("Message cannot be empty")
                
                    S = int(S.strip())
                    if S < 0:
                        raise ValueError("S must be non-negative")
                    
                    C = [int(c.strip()) for c in C.split(',') if c.strip()]
                    if not C or any(c < 1 for c in C):
                        raise ValueError("C must be positive integers")
                except ValueError as ve:
                    st.toast(f"{str(ve)}", icon="⚠️")
                    st.stop()
                
                try:
                    modified_img = stego.embed_in_png(uploaded_file, M.encode(), S, C)
                    st.toast("Message embedded successfully!")
                except ValueError as ve:
                    st.toast(f"{ve}", icon="⚠️")
                    st.stop()

                file_extension = os.path.splitext(uploaded_file.name)[1]
                C_str = ','.join(map(str, C))
                unique_filename = f"{uuid.uuid4()}_{len(M.encode())}_{S}_{C_str}_{file_extension}"
                public_url = bucket.upload_image(client, st.session_state.bucket_name, modified_img, unique_filename)
                bucket.add_image_url(client, st.session_state.bucket_name, public_url)
                st.toast("Image uploaded successfully!", icon=":material/done_outline:")
                st.info("Select the Extract tab to view the image.")

with tab2:
    st.markdown('######')   # add empty space
    st.markdown("#### Step 2. Select an Image, optionally change parameters, and Extract")
    with st.form("extract_form", enter_to_submit=False):
        if st.session_state.selected is not None:
            # Decode the URL before splitting
            decoded_selected = unquote(st.session_state.selected)
            Sp = decoded_selected.split("_")[2]
            Cp = decoded_selected.split("_")[3].split(',')
            Mp = decoded_selected.split("_")[1]
        else:
            Sp, Cp, Mp = "0", ["0"], "0"
        col1, col2, col3 = st.columns(3)
        with col1:
            S = st.text_input("Start bit (S)", value=Sp, placeholder="int")
        with col2:
            C = st.text_input("Mode (C)", value=','.join(Cp), placeholder="int or list of int (8 or 8,16,24)")
        with col3:
            M_len = st.text_input("Message Length (in Bytes)", value=Mp, placeholder="int")
        pad1, col, pad2 = st.columns([1,1,1])
        with col:
            submit = st.form_submit_button("Extract", use_container_width=True)
        if submit:
            if st.session_state.selected:
                try:
                    S = int(S.strip())
                    if S < 0:
                        raise ValueError("S must be non-negative")
                    C = [int(c.strip()) for c in C.split(',') if c.strip()]
                    if not C or any(c < 1 for c in C):
                        raise ValueError("C must be positive integers")
                    M_len = int(M_len.strip())
                    if M_len < 1:
                        raise ValueError("M_len must be positive")
                except ValueError as ve:
                    st.toast(f"{str(ve)}", icon="⚠️")
                    st.stop()
                image_bytes = bucket.download_image(client, st.session_state.bucket_name, st.session_state.selected)
                msg = stego.extract_from_png(image_bytes, S, C, M_len * 8)
                try:
                    st.success(f"Message: {msg.decode('utf-8')}")
                except UnicodeDecodeError:
                    st.error(f"Extraction failed or message is not UTF-8: {msg}")
                    st.stop()
            else:
                st.warning("Please select an image first!")

    st.markdown('######')   # add empty space
    image_urls = bucket.get_image_urls(client, st.session_state.bucket_name)
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