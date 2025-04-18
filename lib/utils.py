# 3rd party lib
import streamlit as st
# app lib
from app import get_gcs_client
import lib.bucket as bucket

client = get_gcs_client()

def toggle_show_download(key_id):
    # Initialize the set if it doesn't exist
    if "show_download_for" not in st.session_state:
        st.session_state.show_download_for = set()
    # Toggle the key_id in the set
    if key_id in st.session_state.show_download_for:
        st.session_state.show_download_for.remove(key_id)
    else:
        st.session_state.show_download_for.add(key_id)

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
                    # Ensure show_download_for is initialized
                    if "show_download_for" not in st.session_state:
                        st.session_state.show_download_for = set()
                    if key_id in st.session_state.show_download_for:
                        # Show download buttons for private and public keys
                        public_key_data = bucket.download_file(client, st.session_state.bucket_name, public_key_file)
                        private_key_data = bucket.download_file(client, st.session_state.bucket_name, private_key_file)
                        
                        st.download_button(
                            label="Download Private Key",
                            data=private_key_data,
                            file_name=f"private_key_{key_id}.enc",
                            mime="application/octet-stream",
                            key=f"download_private_{key_id}"
                        )
                        st.download_button(
                            label="Download Public Key",
                            data=public_key_data,
                            file_name=f"public_key_{key_id}.pem",
                            mime="application/octet-stream",
                            key=f"download_public_{key_id}"
                        )
                    else:
                        # Show "Download" button to toggle visibility
                        st.button("Download", key=f"download_asym_{key_id}", use_container_width=True, on_click=lambda kid=key_id: toggle_show_download(kid))
                with col3:
                    if st.button("Delete", key=f"delete_asym_{key_id}", use_container_width=True):
                        bucket.delete_file(client, st.session_state.bucket_name, public_key_file)
                        bucket.delete_file(client, st.session_state.bucket_name, private_key_file)
                        # Clean up session state
                        if "show_download_for" in st.session_state and key_id in st.session_state.show_download_for:
                            st.session_state.show_download_for.remove(key_id)
                        st.toast(f"Asymmetric key {key_id} deleted.", icon=":material/delete:")
                        st.rerun()
    else:
        st.info(f"No {key_type} keys generated yet.")