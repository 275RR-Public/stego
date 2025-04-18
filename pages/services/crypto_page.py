# 3rd party lib
import streamlit as st
# std lib
import uuid, os
# app lib
from app import get_gcs_client
import lib.bucket as bucket
import lib.crypto as crypto
import lib.sanitize as sanitize
import lib.utils as utils

client = get_gcs_client()
sub = st.experimental_user.sub

# Initialize session state variable if it doesn't exist
if "file_uploaded" not in st.session_state:
    st.session_state.file_uploaded = False
if "hash_info" not in st.session_state:
    st.session_state.hash_info = None
if 'clicked' not in st.session_state:
    st.session_state.clicked = False

with st.sidebar:
    st.write("Cryptography Tips:")
    st.write("1. Manage your files in 'Manage Files': Upload files for encryption, download them, or delete them when no longer needed.")
    st.write("2. Generate keys in 'Manage Keys': Create symmetric keys (AES-128, AES-256, 3-DES) or asymmetric key pairs (RSA-2048) for encryption and decryption.")
    st.write("3. Under 'Symmetric' or 'Asymmetric': Secure your files with 'Symmetric Encryption' and recover them using 'Symmetric Decryption'. For asymmetric operations, use 'Asymmetric Encryption' and 'Asymmetric Decryption'.")
    st.write("4. Additionally, compute and compare file hashes in 'Hashing' to verify integrity, and generate secure passwords in 'Passwords'.")

st.header(":material/lock: Cryptography")
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["**Manage Files**", "**Manage Keys**", "**Symmetric**", "**Asymmetric**", "**Hashing**", "**Passwords**"])

with tab1:
    st.subheader("File Management")
    st.markdown('######')   # add empty space
    # Show file uploader only if no file has been uploaded yet
    if not st.session_state.file_uploaded:
        uploaded_file = st.file_uploader("Upload a file to your Account", type=None)
        if uploaded_file is not None:
            filename = uploaded_file.name
            file_path = f"users/{sub}/files/{filename}"
            result = bucket.upload_file(client, st.session_state.bucket_name, file_path, uploaded_file)
            if result is not None:
                # Mark upload as complete and rerun to refresh the app
                st.session_state.file_uploaded = True
                st.rerun()
            else:
                st.toast("Problem uploading file. Try again later.", icon="⚠️")
    else:
        # Display success message and option to upload another file
        st.toast("File uploaded successfully!", icon=":material/done_outline:")
        if st.button("Upload another file"):
            st.session_state.file_uploaded = False
            st.rerun()

    st.markdown('######')   # add empty space
    # List User Files
    file_list = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/files/")
    if file_list:
        col1, col2, col3 = st.columns([4, 1, 1], vertical_alignment="bottom")
        selected_file = col1.selectbox("Download or Delete a file from your Account", file_list, format_func=lambda x: x.split('/')[-1])
        if selected_file:
            file_data = bucket.download_file(client, st.session_state.bucket_name, selected_file)
            filename = selected_file.split('/')[-1]
            col2.download_button(
                label="Download",
                data=file_data,
                file_name=filename,
                mime="application/octet-stream",
                use_container_width=True
            )
            delete_result = col3.button("Delete", key=f"delete_file_{selected_file}", use_container_width=True)
            if delete_result:
                bucket.delete_file(client, st.session_state.bucket_name, selected_file)
                st.toast(f"File {filename} deleted.", icon=":material/delete:")
                st.rerun()
    else:
        st.info("No files uploaded yet.")

with tab2:
    st.subheader("Key Management")
    st.markdown('######')   # add empty space
    st.write(":small[Generate Keys]")
    col1, col2 = st.columns(2, vertical_alignment="bottom")
    with col1:
        with st.form("generate_symmetric_key"):
            algorithm = st.selectbox("Algorithm", ["AES-128", "AES-256", "3-DES"], label_visibility="collapsed")
            generate_sym_button = st.form_submit_button("Generate Symmetric Key", use_container_width=True)
            if generate_sym_button:
                encrypted_sym_key = crypto.generate_and_encrypt_symmetric_key(algorithm, st.session_state.encryption_key)
                key_id = str(uuid.uuid4())
                file_path = f"users/{sub}/keys/symmetric_key_{algorithm}_{key_id}.key"
                bucket.upload_file(client, st.session_state.bucket_name, file_path, encrypted_sym_key)
                st.toast("Symmetric key generated and stored.", icon=":material/done_outline:")
                st.rerun()

    with col2:
        with st.form("generate_asymmetric_key"):
            st.text_input("RSA-2048", disabled=True, label_visibility="collapsed", value="RSA-2048")
            generate_asym_button = st.form_submit_button("Generate Asymmetric Key Pair", use_container_width=True)
            if generate_asym_button:
                public_pem, encrypted_private = crypto.generate_and_encrypt_asymmetric_key_pair(st.session_state.encryption_key)
                key_id = str(uuid.uuid4())
                public_file_path = f"users/{sub}/keys/public_key_{key_id}.pem"
                private_file_path = f"users/{sub}/keys/private_key_{key_id}.enc"
                bucket.upload_file(client, st.session_state.bucket_name, public_file_path, public_pem)
                bucket.upload_file(client, st.session_state.bucket_name, private_file_path, encrypted_private)
                st.toast("RSA key pair generated and stored.", icon=":material/done_outline:")
                st.rerun()
    
    st.markdown('######')   # add empty space
    st.write(":small[Existing Symmetric Keys by stored ID]")
    sym_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/symmetric_key_")
    utils.display_keys_with_delete(sym_keys, "symmetric")

    st.write(":small[Existing Asymmetric Key Pairs by stored ID]")
    asym_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/public_key_")
    utils.display_keys_with_delete(asym_keys, "asymmetric")

with tab3:
    # Get existing filenames for sanitization
    file_list = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/files/")
    existing_filenames = [os.path.basename(f) for f in file_list]

    # Symmetric Encryption Expander
    with st.expander("Symmetric File Encryption"):
        st.markdown('######')   # add empty space
        files = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/files/")
        file_options = [f for f in files if not f.endswith('.enc')]
        if not file_options:
            st.warning("No files available to encrypt. Upload a file in 'File Management'.")
        else:
            col1, col2 = st.columns(2)
            selected_file = col1.selectbox("Select a file to encrypt", file_options, key="enc_file", format_func=lambda x: x.split('/')[-1])

            col3, col4 = st.columns(2)
            with col3:
                algorithm = st.selectbox("Algorithm", ["AES-128", "AES-256", "3-DES"], key="enc_algo")

            if algorithm.startswith("AES"):
                mode_options = ["CBC", "GCM"]
            else:
                mode_options = ["CBC"]
            with col4:
                mode = st.selectbox("Block Mode", mode_options, key="enc_mode")

            sym_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/symmetric_key_{algorithm}_")
            key_options = [k.split('/')[-1] for k in sym_keys]
            if not key_options:
                st.warning(f"No {algorithm} keys available. Generate one in 'Key Management'.")
            else:
                selected_key = st.selectbox("Select a symmetric key", key_options, key="enc_key")

                default_base_output = selected_file.split('/')[-1]
                base_output_filename = col2.text_input("Base output filename", value=default_base_output, key="enc_output",
                                                     help="The suffix '.enc' will be appended to the base filename.")

                st.markdown('######')   # add empty space
                _, col5, _ = st.columns([1,2,1])
                if col5.button("Encrypt", use_container_width=True):
                    output_filename = sanitize.sanitize_and_validate_filename(base_output_filename, existing_filenames, suffix=".enc")
                    file_data = bucket.download_file(client, st.session_state.bucket_name, selected_file)
                    key_path = f"users/{sub}/keys/{selected_key}"
                    encrypted_sym_key = bucket.download_file(client, st.session_state.bucket_name, key_path)
                    sym_key = crypto.decrypt_data(st.session_state.encryption_key, encrypted_sym_key)
                    encrypted_data = crypto.encrypt_symmetric(file_data, sym_key, algorithm, mode)
                    output_path = f"users/{sub}/files/{output_filename}"
                    bucket.upload_file(client, st.session_state.bucket_name, output_path, encrypted_data)
                    st.toast(f"File encrypted and saved as {output_filename}.", icon=":material/done_outline:")
                    st.rerun()

    # Symmetric Decryption Expander
    with st.expander("Symmetric File Decryption"):
        st.markdown('######')   # add empty space
        enc_files = [f for f in files if f.endswith('.enc') and not f.endswith('_rsa.enc')]
        if not enc_files:
            st.warning("No encrypted files available to decrypt.")
        else:
            col1, col2 = st.columns(2)
            selected_enc_file = col1.selectbox("Select an encrypted file", enc_files, key="dec_file", format_func=lambda x: x.split('/')[-1])
            
            col3, col4 = st.columns(2)
            with col3:
                algorithm = st.selectbox("Algorithm", ["AES-128", "AES-256", "3-DES"], key="dec_algo")

            if algorithm.startswith("AES"):
                mode_options = ["CBC", "GCM"]
            else:
                mode_options = ["CBC"]
            with col4:
                mode = st.selectbox("Block Mode", mode_options, key="dec_mode")

            sym_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/symmetric_key_{algorithm}_")
            key_options = [k.split('/')[-1] for k in sym_keys]
            if not key_options:
                st.warning(f"No {algorithm} keys available.")
            else:
                selected_key = st.selectbox("Select a symmetric key", key_options, key="dec_key")

                suggested_output = selected_enc_file.split('/')[-1][:-4]  # Remove '.enc'
                output_filename = col2.text_input("Output filename", value=suggested_output, key="dec_output")

                st.markdown('######')   # add empty space
                _, col5, _ = st.columns([1,2,1])
                if col5.button("Decrypt", use_container_width=True):
                    safe_output_filename = sanitize.sanitize_and_validate_filename(output_filename, existing_filenames)
                    encrypted_data = bucket.download_file(client, st.session_state.bucket_name, selected_enc_file)
                    key_path = f"users/{sub}/keys/{selected_key}"
                    encrypted_sym_key = bucket.download_file(client, st.session_state.bucket_name, key_path)
                    sym_key = crypto.decrypt_data(st.session_state.encryption_key, encrypted_sym_key)
                    try:
                        decrypted_data = crypto.decrypt_symmetric(encrypted_data, sym_key, algorithm, mode)
                    except Exception as e:
                        st.error(f"Decryption failed: {str(e)}")
                    else:
                        output_path = f"users/{sub}/files/{safe_output_filename}"
                        bucket.upload_file(client, st.session_state.bucket_name, output_path, decrypted_data)
                        st.toast(f"File decrypted and saved as {safe_output_filename}.", icon=":material/done_outline:")
                        st.rerun()

with tab4:
    # Asymmetric Encryption
    with st.expander("Asymmetric File Encryption"):
        st.markdown('######')   # add empty space
        files = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/files/")
        file_options = [f for f in files if not f.endswith('_rsa.enc')] # Exclude already encrypted files
        if not file_options:
            st.warning("No files available to encrypt.")
        else:
            col1, col2 = st.columns(2)
            selected_file = col1.selectbox("Select a file to encrypt", file_options, key="asym_enc_file", format_func=lambda x: x.split('/')[-1])
            
            # List public keys
            public_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/public_key_")
            key_pair_ids = [k.split('_')[-1].split('.')[0] for k in public_keys]
            if not key_pair_ids:
                st.warning("No RSA key pairs available. Generate one in 'Key Management'.")
            else:
                selected_key_id = st.selectbox("Select a key pair ID", key_pair_ids, key="asym_enc_key")
                default_base_output = selected_file.split('/')[-1]
                base_output_filename = col2.text_input("Base output filename", value=default_base_output, key="asym_enc_output",
                                                     help="The suffix '_rsa.enc' will be appended to the base filename.")
                
                st.markdown('######')   # add empty space
                _, col5, _ = st.columns([1,2,1])
                if col5.button("Encrypt", key="asym_enc_button", use_container_width=True):
                    output_filename = sanitize.sanitize_and_validate_filename(base_output_filename, existing_filenames, suffix="_rsa.enc")
                    # Load public key
                    public_key_path = f"users/{sub}/keys/public_key_{selected_key_id}.pem"
                    public_pem = bucket.download_file(client, st.session_state.bucket_name, public_key_path)
                    try:
                        public_key = crypto.load_public_key(public_pem)
                    except ValueError as e:
                        st.error(str(e))
                        st.stop()
                    
                    # Load file data
                    file_data = bucket.download_file(client, st.session_state.bucket_name, selected_file)
                    encrypted_data = crypto.encrypt_asymmetric(file_data, public_key)
                    output_path = f"users/{sub}/files/{output_filename}"
                    bucket.upload_file(client, st.session_state.bucket_name, output_path, encrypted_data)
                    st.toast(f"File encrypted and saved as {output_filename}.", icon=":material/done_outline:")
                    st.rerun()

    # Asymmetric Decryption
    with st.expander("Asymmetric File Decryption"):
        st.markdown('######')   # add empty space
        enc_files = [f for f in files if f.endswith('_rsa.enc')] # Include only encrypted files
        if not enc_files:
            st.warning("No asymmetrically encrypted files available.")
        else:
            col1, col2 = st.columns(2)
            selected_enc_file = col1.selectbox("Select an encrypted file", enc_files, key="asym_dec_file", format_func=lambda x: x.split('/')[-1])
            
            # List private keys
            private_keys = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/keys/private_key_")
            key_pair_ids = [k.split('_')[-1].split('.')[0] for k in private_keys if k.endswith('.enc')]
            if not key_pair_ids:
                st.warning("No RSA private keys available.")
            else:
                selected_key_id = st.selectbox("Select a key pair ID", key_pair_ids, key="asym_dec_key")
                suggested_output = selected_enc_file.split('/')[-1][:-8]  # Remove '_rsa.enc'
                output_filename = col2.text_input("Output filename", value=suggested_output, key="asym_dec_output")
                
                st.markdown('######')   # add empty space
                _, col5, _ = st.columns([1,2,1])
                if col5.button("Decrypt", key="asym_dec_button", use_container_width=True):
                    # Load and decrypt private key
                    safe_output_filename = sanitize.sanitize_and_validate_filename(output_filename, existing_filenames)
                    private_key_path = f"users/{sub}/keys/private_key_{selected_key_id}.enc"
                    encrypted_private_pem = bucket.download_file(client, st.session_state.bucket_name, private_key_path)
                    private_pem = crypto.decrypt_data(st.session_state.encryption_key, encrypted_private_pem)
                    try:
                        private_key = crypto.load_private_key(private_pem)
                    except ValueError as e:
                        st.error(str(e))
                        st.stop()
                    
                    # Load encrypted data
                    encrypted_data = bucket.download_file(client, st.session_state.bucket_name, selected_enc_file)
                    try:
                        decrypted_data = crypto.decrypt_asymmetric(encrypted_data, private_key)
                    except Exception as e:
                        st.error(f"Decryption failed: {str(e)}")
                    else:
                        output_path = f"users/{sub}/files/{safe_output_filename}"
                        bucket.upload_file(client, st.session_state.bucket_name, output_path, decrypted_data)
                        st.toast(f"File decrypted and saved as {safe_output_filename}.", icon=":material/done_outline:")
                        st.rerun()

with tab5:
    st.subheader("File Hashing")
    st.markdown('######')   # add empty space
    files = bucket.list_files(client, st.session_state.bucket_name, f"users/{sub}/files/")
    if not files:
        st.warning("No files available. Please upload files in the File Management section.")
    else:
        with st.container(border=True):
            col1, col2, col3 = st.columns([2,1,1], vertical_alignment="bottom")
            selected_file = col1.selectbox("Select a file to hash", files, format_func=lambda x: os.path.basename(x))
            algorithm = col2.selectbox("Select algorithm", ["SHA2-256", "SHA3-256"])
            if col3.button("Compute Hash", use_container_width=True):
                file_data = bucket.download_file(client, st.session_state.bucket_name, selected_file)
                hash_value = crypto.compute_hash(file_data, algorithm)
                st.session_state.hash_info = {
                    'file': selected_file,
                    'algorithm': algorithm,
                    'hash': hash_value
                }

        st.markdown('######')   # add empty space
        if st.session_state.hash_info is not None:
            st.text_input(
                f'Computed Hash for "{os.path.basename(st.session_state.hash_info['file'])}" with {st.session_state.hash_info['algorithm']}',
                value=st.session_state.hash_info['hash'],
                disabled=True
            )
        
        compare_hash = st.text_input("Enter hash to compare", max_chars=64, help="Enter a 64-character hexadecimal hash.")
        _, col5, _ = st.columns([1,2,1])
        if col5.button("Compare", use_container_width=True):
            if 'hash_info' not in st.session_state:
                st.warning("Please compute the hash first.")
            else:
                clean_hash = sanitize.sanitize_and_validate_hash(compare_hash)
                if clean_hash:
                    if clean_hash == st.session_state.hash_info['hash']:
                        st.success(f'Hashes MATCH for "{os.path.basename(st.session_state.hash_info['file'])}"')
                    else:
                        st.error(f'Hashes DO NOT MATCH for "{os.path.basename(st.session_state.hash_info['file'])}"')
                else:
                    st.warning("Invalid hash format. Please enter a 64-character hexadecimal string.")

with tab6:
    st.subheader("Password Generation")
    st.markdown('######')   # add empty space
    with st.container(border=True):
        st.write(":small[Character Sets]")
        col1, col2 = st.columns(2)
        with col1:
            use_lower = st.checkbox("Use Lowercase", value=True, help="a-z")
            use_upper = st.checkbox("Use Uppercase", value=True, help="A-Z")
        with col2:
            use_digits = st.checkbox("Use Digits", value=True, help="0-9")
            use_special = st.checkbox("Use Special characters", value=True, help="! @ # $ % ^ & * ( )")
    col3, col4 = st.columns(2, vertical_alignment="bottom")
    with col3:
        length = st.number_input("Password length", min_value=8, max_value=128, value=16, help="7 < length < 129")
    with col4:
        result = st.button("Generate Password", use_container_width=True)
    
    st.markdown('######')   # add empty space
    if result:
        try:
            password = crypto.generate_password(length, use_lower, use_upper, use_digits, use_special)
            st.code(password, language=None)
        except ValueError as e:
            st.error(str(e))