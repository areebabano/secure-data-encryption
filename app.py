import streamlit as st
import time
from datetime import datetime
from streamlit_lottie import st_lottie
import requests

from authenticator import hash_passkey, check_passkey, authenticate_user, register_user
from encryptor import encrypt_data, decrypt_data
from storage import load_data, save_data
from utils import check_lockout

stored_data = load_data()

if "login_status" not in st.session_state:
    st.session_state.login_status = False
    st.session_state.current_user = ""
    st.session_state.attempts = 0
    st.session_state.page = "Home"
    st.session_state.theme = "Light"

def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_login = load_lottie_url("https://assets1.lottiefiles.com/packages/lf20_jcikwtux.json")

# Sidebar
def sidebar_navigation():
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=150)
        st.markdown("## 🔐 Secure Data App")

        theme = st.radio("🌓 Theme", ["Light", "Dark"])
        st.session_state["theme"] = theme

        if st.session_state.login_status:
            st.success(f"✅ Logged in as: `{st.session_state.current_user}`")
            st.session_state.page = st.radio("📍 Navigate", ["Home", "Insert Data", "Retrieve Data"])
            if st.button("🚪 Logout"):
                st.session_state.login_status = False
                st.session_state.current_user = ""
                st.session_state.attempts = 0
                st.session_state.page = "Login"
                st.rerun()
        else:
            st.session_state.page = "Login"

# Login/Register Page
def login_page():
    st.header("🔐 Login or Register")
    st_lottie(lottie_login, height=400, key="login_animation")
    action = st.radio("Choose an action:", ["Login", "Register"])

    if action == "Login":
        username = st.text_input("👤 Username", placeholder="Enter your username", key="login_username")
        password = st.text_input("🔑 Password", type="password", placeholder="Enter your password", key="login_password")

        if st.button("🔓 Login", key="login_submit"):
            with st.spinner("Authenticating..."):
                time.sleep(1)
                if authenticate_user(username, password, stored_data["users"]):
                    st.success("🎉 Logged In Successfully!")
                    st.session_state.login_status = True
                    st.session_state.current_user = username
                    st.session_state.attempts = 0
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials. Please try again.")

    else:
        username = st.text_input("👤 New Username", placeholder="Create your username", key="register_username")
        password = st.text_input("🔑 New Password", type="password", placeholder="Create a strong password", key="register_password")

        if st.button("📝 Register", key="register_submit"):
            success, msg = register_user(username, password, stored_data["users"])
            if success:
                stored_data["users"][username]["data"] = {}
                save_data(stored_data)
                st.success("✅ " + msg)
            else:
                st.warning("⚠️ " + msg)

# Home Page
def home_page():
    st.header("🏡 Welcome to the Secure Data App")
    st.markdown("Use the sidebar to securely **store** or **retrieve** encrypted data.")
    st_lottie(lottie_login, height=250)

# Insert Data Page
def insert_data_page():
    st.header("🔏 Store New Data")
    text = st.text_input("💬 Enter Data", placeholder="Type the data to encrypt here...")
    passkey = st.text_input("🔑 Enter Passkey", type="password", placeholder="Create a passkey to protect this data", key="insert_passkey")

    if st.button("📥 Store Data"):
        if not text or not passkey:
            st.warning("⚠️ Please complete both fields.")
            return

        with st.spinner("Encrypting and storing your data..."):
            encrypted = encrypt_data(text)
            hashed = hash_passkey(passkey)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            stored_data["users"][st.session_state.current_user]["data"] = {
                "encrypted_text": encrypted,
                "passkey": hashed,
                "timestamp": timestamp
            }
            save_data(stored_data)
            st.success(f"✅ Data stored successfully at {timestamp}")

# Retrieve Data Page
def retrieve_data_page():
    st.header("🔓 Retrieve Encrypted Data")
    locked, remaining = check_lockout()
    if locked:
        st.warning(f"🔒 Too many failed attempts. Try again in {int(remaining)} seconds.")
        return

    passkey = st.text_input("🔐 Enter Passkey", type="password", placeholder="Enter your passkey to decrypt", key="retrieve_passkey")

    if st.button("🔍 Retrieve Data"):
        user_data = stored_data["users"][st.session_state.current_user].get("data")
        if not user_data:
            st.warning("⚠ No data found. Please store some data first.")
            return

        with st.spinner("Verifying passkey..."):
            time.sleep(1)
            if not check_passkey(passkey, user_data["passkey"]):
                st.session_state.attempts += 1
                st.error(f"❌ Incorrect passkey. Attempt {st.session_state.attempts}/3")
                if st.session_state.attempts >= 3:
                    st.session_state.lockout_time = time.time()
            else:
                decrypted = decrypt_data(user_data["encrypted_text"])
                timestamp = user_data.get("timestamp", "Unknown")
                st.balloons()
                st.success("✅ Decrypted Data:")
                st.code(decrypted, language="text")
                st.info(f"📅 Stored At: {timestamp}")
                st.session_state.attempts = 0

# Main App Flow
st.set_page_config(page_title="Secure Data App", layout="centered")
sidebar_navigation()

if st.session_state.page == "Login":
    login_page()
elif st.session_state.page == "Home":
    home_page()
elif st.session_state.page == "Insert Data":
    insert_data_page()
elif st.session_state.page == "Retrieve Data":
    retrieve_data_page()

