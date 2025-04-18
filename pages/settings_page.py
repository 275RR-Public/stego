import streamlit as st
from app import get_gcs_client
import lib.bucket as bucket

client = get_gcs_client()
sub = st.experimental_user.sub

if "confirm_delete" not in st.session_state:
    st.session_state.confirm_delete = None

st.header(":material/settings: Account Settings")
st.info(f"You are logged in as {st.experimental_user.name}.")

st.markdown('######')   # add empty space
st.subheader("Delete ALL Files and Keys")
st.write("This will delete all your uploaded files and generated keys.")
st.write("This action cannot be undone.")

if st.button("Delete ALL Files and Keys", type="primary"):
    st.session_state.confirm_delete = True

if st.session_state.get("confirm_delete", False):
    st.error("Are you sure you want to delete all your files and keys? This action cannot be undone.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Yes, delete"):
            bucket.delete_folder(client, st.session_state.bucket_name, f"users/{sub}/files/")
            bucket.delete_folder(client, st.session_state.bucket_name, f"users/{sub}/keys/")
            st.session_state.confirm_delete = False
            st.success("All files and keys have been deleted.")
    with col2:
        if st.button("No, cancel"):
            st.session_state.confirm_delete = False
            st.rerun()