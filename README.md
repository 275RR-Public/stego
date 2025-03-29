# Image Steganography on Streamlit

*Steganography is the practice of concealing an object within another object, making the presence of the hidden object imperceptible to an unsuspecting observer.*

In our example, we are hiding an ASCII message in a PNG image.

## Public Website

Visit at https://imgstego.streamlit.app/

Requirements:
1. Allow anyone to view stego images.
2. After login, allow user to create stego images.

## Dev Environment Setup
To run Streamlit locally:

```bash
# Create a virtual environment
python -m venv myenv

# Windows - Activate
myenv\Scripts\activate

# MacOS and Linux - Activate
source myenv/bin/activate
```

```bash
# Install dependencies
pip install -r requirements.txt
```

Get a [Google Cloud Trial Account](https://console.cloud.google.com/)

Setup your [Google Cloud Storage Bucket](https://docs.streamlit.io/develop/tutorials/databases/gcs)

Setup your [Google Cloud OAuth 2.0](https://docs.streamlit.io/develop/api-reference/user/st.login)

```bash
# Insert Google secrets
mkdir .streamlit
touch .streamlit/secrets.toml
```

```bash
# Run Steamlit locally
streamlit run app.py
```
