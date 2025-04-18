# Import required libraries
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
from dotenv import load_dotenv
import os
import json

# Load environment variables
load_dotenv()

# Get encryption key from environment variables
key = os.getenv("SECRET_KEY")

# Initialize Fernet cipher for encryption/decryption
cipher = Fernet(key)

# Initialize failed attempts tracking on first load
if "first_load_done" not in st.session_state:
    st.session_state.first_load_done = True
    with open("attempts.json", "w") as f:
        json.dump({"failed_attempts": 0}, f)

# Load the current number of failed attempts
with open("attempts.json", "r") as f:
    failed_attempts = json.load(f)["failed_attempts"]
    
# Initialize user dictionary
with open("user.json", "r") as f:
    user = json.load(f)

# Load stored encrypted data
with open("stored_data.json", "r") as f:
    stored_data = json.load(f)

def hash_passkey(passkey):
    """Hash the passkey using SHA-256 for secure storage"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    """Encrypt the input text using Fernet symmetric encryption"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(passkey):
    """
    Decrypt data using the provided passkey.
    Updates failed attempts counter and returns None if passkey is incorrect.
    """
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    if hashed_passkey in stored_data:
        # Reset failed attempts on successful decryption
        failed_attempts = 0
        with open("attempts.json", "w") as f:
            json.dump({"failed_attempts": failed_attempts}, f)
        return cipher.decrypt(stored_data[hashed_passkey]["encrypted_text"].encode()).decode()
    else:
        # Increment failed attempts on incorrect passkey
        failed_attempts += 1
        with open("attempts.json", "w") as f:
            json.dump({"failed_attempts": failed_attempts}, f)
    return None

# Set up the Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Delete Data", "Edit Data", "Login", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)


# Home page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data page
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter your Data: ")
    passkey = st.text_input("Enter Passkey: ", type="password")

    if st.button("Encrypt & Save"):
        if user["name"] and user["password"]:  # Verify user is logged in
            if user_data and passkey:
                if hash_passkey(passkey) in stored_data:
                    st.error("❌ Passkey already exists!")
                else:
                    # Hash passkey and encrypt data
                    hashed_passkey = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)

                    # Store encrypted data
                    stored_data[hashed_passkey] = {"encrypted_text" : encrypted_text, "passkey": hashed_passkey}
                    with open("stored_data.json", "w") as f:
                        json.dump(stored_data, f)
                    st.success("✅ Data Stored Securely")
            else: 
                st.error("❌ Both fields are required!")
        else:
            st.error("❌ Please login first!")

# Retrieve Data page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieved Your Data")
    passkey = st.text_input("Enter Passkey: ", type="password")

    decrypt_btn = st.button("Decrypt")

    if decrypt_btn:
        if user["name"] and user["password"]:  # Verify user is logged in
            if passkey:
                # Attempt to decrypt data
                decrypted_text = decrypt_data(passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    # Show remaining attempts before lockout
                    st.error(f"❌ Incorrect Passkey! Attempts remaining: {3 - failed_attempts}")

                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to login page.")
                        with open("user.json", "w") as f:
                            user = {"name": "", "password": ""}
                            json.dump(user, f)
                        with open("attempts.json", "w") as f:
                            failed_attempts = 0
                            json.dump({"failed_attempts": failed_attempts}, f)
            else:
                st.error("❌ Passkey is required!")
        else:
            st.error("❌ Please login first!")

# Login page - shown when explicitly selected
elif choice == "Login":
    st.subheader("🔑 Reauthorization required")
    login_pass = st.text_input("Enter Master Password: ", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # TODO: Replace with secure password handling
            # Reset failed attempts on successful login
            failed_attempts = 0
            with open("attempts.json", "w") as f:
                json.dump({"failed_attempts": failed_attempts}, f)

            # Save user data
            with open("user.json", "w") as f:
                user = {"name": "Admin", "password": login_pass}
                json.dump(user, f)

            st.success("✅ Authorization successfully!")
        else:
            st.error("❌ Incorrect Password")

elif choice == "Delete Data":
    st.subheader("🗑️ Delete Data")
    passkey = st.text_input("Enter Passkey: ", type="password")
    if st.button("Delete"):
        if user["name"] and user["password"]:  # Verify user is logged in
            if passkey:
                if hash_passkey(passkey) in stored_data:
                    # Delete data from stored_data.json
                    del stored_data[hash_passkey(passkey)]
                    with open("stored_data.json", "w") as f:
                        json.dump(stored_data, f)
                    st.success("✅ Data deleted successfully!")
                else:
                    st.error("❌ Passkey not found!")
            else:
                st.error("❌ Passkey is required!")
        else:
            st.error("❌ Please login first!")
    

elif choice == "Edit Data":
    st.subheader("✏️ Edit Data")
    passkey = st.text_input("Enter Passkey: ", type="password")
    edit_text = st.text_area("Enter your Data: ")
    if st.button("Edit"):
        if user["name"] and user["password"]:  # Verify user is logged in
            if passkey and edit_text:
                if hash_passkey(passkey) in stored_data:
                    # Edit data in stored_data.json
                    encrypted_text = encrypt_data(edit_text, passkey)
                    with open("stored_data.json", "w") as f:
                        stored_data[hash_passkey(passkey)]["encrypted_text"] = encrypted_text
                        json.dump(stored_data, f)
                    st.success("✅ Data edited successfully!")
                else:
                    st.error("❌ Passkey not found!")
            else:
                st.error("❌ Both fields are required!")
        else:
            st.error("❌ Please login first!")

elif choice == "Logout":
    # Logout functionality
    if user["name"] and user["password"]:  # Verify user is logged in
        # Reset failed attempts on logout
        failed_attempts = 0
        with open("attempts.json", "w") as f:
            json.dump({"failed_attempts": failed_attempts}, f)
        
        # Save user data
        with open("user.json", "w") as f:
            user = {"name": "", "password": ""}
            json.dump(user, f)
        st.success("✅ Logged out successfully!")
    else:
        st.error("❌ You are not logged in!")
