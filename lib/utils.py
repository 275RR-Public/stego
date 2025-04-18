# 3rd party lib
import streamlit as st
# app lib
from app import get_gcs_client
import lib.bucket as bucket

client = get_gcs_client()

def hide_on_click():
    # Toggle button visibility on click
    st.session_state.clicked = not st.session_state.clicked

def display_keys_with_delete(keys, key_type):
    """
    Display cryptographic keys with options to download and delete them.

    Parameters:
    - keys: List of key file paths in GCS.
    - key_type: String indicating "symmetric" or "asymmetric".
    """
    if keys:
        for key_file in keys:
            if key_type == "symmetric":
                # Extract algorithm and key ID from filename
                algo = key_file.split('_')[-2]
                key_id = key_file.split('_')[-1].split('.')[0]
                display_text = f"{algo}: {key_id}"
                
                # Create three columns: display, download, delete
                col1, col2, col3 = st.columns([4, 1, 1], vertical_alignment="center")
                with col1:
                    st.code(display_text, language=None)
                with col2:
                    # Fetch key data and provide download button
                    key_data = bucket.download_file(client, st.session_state.bucket_name, key_file)
                    st.download_button(
                        label="Download",
                        data=key_data,
                        file_name=f"symmetric_key_{algo}_{key_id}.key",
                        mime="application/octet-stream",
                        key=f"download_symmetric_{key_id}",
                        use_container_width=True
                    )
                with col3:
                    if st.button("Delete", key=f"delete_symmetric_{key_id}", use_container_width=True):
                        bucket.delete_file(client, st.session_state.bucket_name, key_file)
                        st.toast(f"Symmetric key {key_id} deleted.", icon=":material/delete:")
                        st.rerun()

            elif key_type == "asymmetric":
                # Extract key ID from public key filename
                key_id = key_file.split('_')[-1].split('.')[0]
                public_key_file = key_file
                private_key_file = key_file.replace("public_key_", "private_key_").replace(".pem", ".enc")
                
                # Create three columns: display, download, delete
                col1, col2, col3 = st.columns([4, 1, 1], vertical_alignment="center")
                with col1:
                    st.code(f"RSA-2048: {key_id}", language=None)
                with col2:
                    if not st.session_state.clicked:
                        st.button("Download", key=f"download_asym_{key_id}", use_container_width=True, on_click=hide_on_click)
                    if st.session_state.clicked:
                        # Fetch public and private key data
                        public_key_data = bucket.download_file(client, st.session_state.bucket_name, public_key_file)
                        private_key_data = bucket.download_file(client, st.session_state.bucket_name, private_key_file)
                        
                        # Trigger download for private key
                        st.download_button(
                            label="Download Private Key",
                            data=private_key_data,
                            file_name=f"private_key_{key_id}.enc",
                            mime="application/octet-stream",
                            key=f"download_private_{key_id}",
                            on_click=hide_on_click
                        )
                        # Trigger download for public key
                        st.download_button(
                            label="Download Public Key",
                            data=public_key_data,
                            file_name=f"public_key_{key_id}.pem",
                            mime="application/octet-stream",
                            key=f"download_public_{key_id}",
                            on_click=hide_on_click
                        )
                with col3:
                    if st.button("Delete", key=f"delete_asym_{key_id}", use_container_width=True):
                        bucket.delete_file(client, st.session_state.bucket_name, public_key_file)
                        bucket.delete_file(client, st.session_state.bucket_name, private_key_file)
                        st.toast(f"Asymmetric key {key_id} deleted.", icon=":material/delete:")
                        st.rerun()
    else:
        st.info(f"No {key_type} keys generated yet.")