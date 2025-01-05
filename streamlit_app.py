import streamlit as st
import hashlib
import random
import string
import smtplib
from email.mime.text import MIMEText
import base64
from PIL import Image
import io
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Database Setup
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(256), nullable=False)
    profile_photo = Column(LargeBinary, nullable=True)
    public_key = Column(LargeBinary, nullable=True)
    private_key = Column(LargeBinary, nullable=True)
    certificate = Column(LargeBinary, nullable=True)
    created_at = Column(String(50), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Create database engine
engine = create_engine('sqlite:///encryption_app.db', echo=True)
Base.metadata.create_all(engine)

# Create session factory
Session = sessionmaker(bind=engine)

# Initialize session state for login status
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

secrets = st.secrets

SMTP_USERNAME = secrets["SMTP_USERNAME"]
SMTP_PASSWORD = secrets["SMTP_PASSWORD"]

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_otp_email(email, otp, user_name):
    # Create a multipart email message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Your One-Time Password (OTP) for Password Reset"
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    
    # Create the HTML content without the logo
    html_content = f"""
    <html>
        <body>
            <h2>Hello {user_name},</h2>
            <p>We have received a request to reset your password. To ensure the security of your account, please use the One-Time Password (OTP) below:</p>
            <h3>One-Time Password:</h3>
            <span style="text-align:center"> <strong style="font-size: 50px;">{otp}</strong></span>
            <p>This OTP is valid for 5 minutes. Please enter it in the designated field to reset your password.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Thank you for your attention.</p>
            <p>Sincerely,<br>Night Crypt<br><a href="mailto:app.nightcrypt@gmail.com" target="_blank">app.nightcrypt@gmail.com</a></p>
        </body>
    </html>
    """
    
    # Attach the HTML content to the message
    msg.attach(MIMEText(html_content, 'html'))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Error sending email: {e}")
        return False

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def encrypt_message(message, public_key):
    public_key = serialization.load_pem_public_key(public_key)
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None)
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message.encode()),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def main():
    if not st.session_state.logged_in:
        st.set_page_config(page_title="Nightcrypt", page_icon="./assets/LOGO.png")  # Title for the login screen
        st.title("NightCrypt App")  # Title for the login screen
        tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Forgot Password"])
        
        with tab1:
            st.header("Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            
            if st.button("Login", key="login_button"):
                db_session = Session()
                user = db_session.query(User).filter_by(username=username).first()
                if user and user.password == hash_password(password):
                    st.session_state.logged_in = True
                    st.session_state.current_user = username
                    db_session.close()
                    st.rerun()
                else:
                    st.error("Invalid credentials")
                db_session.close()
        
        with tab2:
            st.header("Sign Up")
            new_username = st.text_input("Username", key="signup_username")
            new_email = st.text_input("Email", key="signup_email")
            new_password = st.text_input("Password", type="password", key="signup_password")
            
            if st.button("Sign Up", key="signup_button"):
                db_session = Session()
                existing_user = db_session.query(User).filter_by(username=new_username).first()
                if not existing_user:
                    new_user = User(
                        username=new_username,
                        email=new_email,
                        password=hash_password(new_password)
                    )
                    db_session.add(new_user)
                    try:
                        db_session.commit()
                        st.success("Account created successfully!")
                    except Exception as e:
                        db_session.rollback()
                        st.error(f"Error creating account: {e}")
                else:
                    st.error("Username already exists")
                db_session.close()
        
        with tab3:
            st.header("Forgot Password")
            reset_email = st.text_input("Enter your email")
            if st.button("Send OTP", key="send_otp_button"):
                db_session = Session()
                user = db_session.query(User).filter_by(email=reset_email).first()
                if user:
                    otp = generate_otp()
                    st.session_state.reset_otp = otp
                    st.session_state.reset_username = user.username
                    if send_otp_email(reset_email, otp, user.username):
                        st.success("OTP sent to your email")
                else:
                    st.error("Email not found")
                db_session.close()
            
            otp_input = st.text_input("Enter OTP")
            new_password = st.text_input("New Password", type="password")
            if st.button("Reset Password", key="reset_password_button"):
                if hasattr(st.session_state, 'reset_otp') and \
                   otp_input == st.session_state.reset_otp:
                    # Check if the OTP is still valid (within 5 minutes)
                    if (datetime.now() - st.session_state.otp_timestamp).total_seconds() <= 300:
                        db_session = Session()
                        user = db_session.query(User).filter_by(
                            username=st.session_state.reset_username
                        ).first()
                        if user:
                            user.password = hash_password(new_password)
                            db_session.commit()
                            st.success("Password reset successful")
                        db_session.close()
                    else:
                        st.error("OTP has expired")
                else:
                    st.error("Invalid OTP")
    else:
        st.set_page_config(page_title=f"NightCrypt - {st.session_state.current_user}", page_icon="./assets/LOGO.png")  # Updated page title after login
        st.title(f"NightCrypt - @{st.session_state.current_user}")  # Updated title after login
        db_session = Session()
        current_user = db_session.query(User).filter_by(
            username=st.session_state.current_user
        ).first()
        
        # User Profile Section moved to sidebar
        with st.sidebar:
            if current_user.profile_photo:
                # Display the profile photo as rounded using HTML
                st.markdown(
                    f'<img src="data:image/png;base64,{base64.b64encode(current_user.profile_photo).decode()}" style="border-radius: 50%; width: 150px; height: 150px;" />',
                    unsafe_allow_html=True
                )
            else:
                uploaded_file = st.file_uploader("Upload Profile Photo", type=["jpg", "png", "jpeg"], key="profile_photo_uploader")
                if uploaded_file:
                    image = Image.open(uploaded_file)
                    image = image.resize((150, 150))
                    img_byte_arr = io.BytesIO()
                    image.save(img_byte_arr, format='PNG')
                    current_user.profile_photo = img_byte_arr.getvalue()
                    db_session.commit()
            st.write(f"@{current_user.username}")
            if st.button("Logout"):
                st.session_state.logged_in = False
                db_session.close()
                st.rerun()
        
        # Encryption Sections
        tab1, tab2 = st.tabs(["Caesar Cipher", "RSA"])
        
        with tab1:
            st.header("Caesar Cipher")
            caesar_text = st.text_area("Enter text for Caesar cipher")
            shift = st.number_input("Shift value", min_value=1, max_value=2000, value=3)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Encrypt", key="caesar_encrypt_button"):
                    encrypted = caesar_encrypt(caesar_text, shift)
                    st.code(encrypted)
                    if st.button("Copy Encrypted Text", key="copy_caesar_enc"):
                        st.write(encrypted)
            
            with col2:
                if st.button("Decrypt", key="caesar_decrypt_button"):
                    decrypted = caesar_decrypt(caesar_text, shift)
                    st.code(decrypted)
                    if st.button("Copy Decrypted Text", key="copy_caesar_dec"):
                        st.write(decrypted)
        
        with tab2:
            st.header("RSA Encryption Decryption")
            
            # Option to generate keys and certificate
            if st.button("Generate Keys and Certificate", key="generate_keys_button"):
                # Generate a private key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()
                
                # Create a self-signed certificate
                subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, st.session_state.current_user)])
                issuer = subject
                cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).sign(private_key, hashes.SHA256(), default_backend())
                
                # Save the certificate and private key
                cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
                private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Store the certificate and keys in the user object
                current_user.certificate = cert_pem
                current_user.private_key = private_pem
                current_user.public_key = public_pem
                db_session.commit()
                st.success("Keys and certificate generated successfully!")

            # Current keys section as a dropdown
            with st.expander("Current Keys and Certificate", expanded=False):
                if current_user.certificate:
                    st.subheader("Your Current Certificate:")
                    st.code(current_user.certificate.decode(), language='text')  # Show current certificate
                    
                    # Download certificate button with username
                    st.download_button(
                        "Download Certificate",
                        current_user.certificate,
                        f"certificate_{st.session_state.current_user}_.pem"
                    )
                
                if current_user.public_key:
                    st.subheader("Your Current Public Key:")
                    st.code(current_user.public_key.decode(), language='text')  # Show current public key
                
                if current_user.private_key:
                    st.subheader("Your Current Private Key:")
                    st.code(current_user.private_key.decode(), language='text')  # Show current private key
                
                if not current_user.certificate and not current_user.public_key and not current_user.private_key:
                    st.write("No keys or certificate generated yet.")
            
            # Key download buttons with username
            col1, col2, col3 = st.columns(3)
            with col1:
                if current_user.public_key:  # Check if public key is not None
                    st.download_button(
                        "Download Public Key",
                        current_user.public_key,
                        f"public_key_{st.session_state.current_user}_.pem",
                        key="download_public_key"  # Unique key for public key download
                    )
                else:
                    st.warning("Public key not available for download.")
            
            with col2:
                if current_user.private_key:  # Check if private key is not None
                    st.download_button(
                        "Download Private Key",
                        current_user.private_key,
                        f"private_key_{st.session_state.current_user}_.pem",
                        key="download_private_key"  # Unique key for private key download
                    )
                else:
                    st.warning("Private key not available for download.")
            with col3:
                if current_user.certificate:
                    st.download_button(
                        "Download Certificate",
                        current_user.certificate,
                        f"certificate_{st.session_state.current_user}_.pem",
                        key="download_certificate"  # Unique key for certificate download
                    )
                else:
                    st.warning("Certificate not available for download.")

            # Upload recipient's certificate or public key for encryption
            if 'recipient_cert_uploaded' not in st.session_state or not st.session_state.recipient_cert_uploaded:
                st.info("Please upload the recipient's certificate or public key to enable encryption.")  # Info message
            uploaded_recipient_cert = st.file_uploader("Upload Recipient's Certificate or Public Key", type=["pem"], key="recipient_cert_upload")
            if uploaded_recipient_cert:
                st.session_state.recipient_cert_uploaded = True  # Set state to indicate the file has been uploaded
                cert_data = uploaded_recipient_cert.read()
                try:
                    # Attempt to load the recipient's certificate
                    recipient_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    recipient_public_key = recipient_cert.public_key()
                    st.success("Recipient's certificate uploaded successfully! Public key retrieved for encryption.")
                    
                except Exception:
                    # If loading as a certificate fails, try loading as a public key
                    try:
                        recipient_public_key = serialization.load_pem_public_key(cert_data, default_backend())
                        st.success("Public key uploaded successfully for encryption.")
                    except Exception as e:
                        st.error("Failed to upload recipient's certificate or public key: " + str(e))
                        recipient_public_key = None

                if recipient_public_key:
                    # Message input for encryption
                    message_to_encrypt = st.text_area("Enter message to encrypt for recipient:")
                    if st.button("Encrypt Message"):
                        recipient_public_pem = recipient_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        encrypted_message = encrypt_message(message_to_encrypt, recipient_public_pem)
                        st.success("Message encrypted successfully!")
                        st.code(encrypted_message)  # Display the encrypted message
            
            # Decrypt message section for the recipient
            st.subheader("Decrypt Message")
            encrypted_message_input = st.text_area("Enter the encrypted message:")
            if st.button("Decrypt Message"):
                if current_user.private_key:
                    try:
                        decrypted_message = decrypt_message(encrypted_message_input, current_user.private_key)
                        st.success("Message decrypted successfully!")
                        st.code(decrypted_message,language='text')  # Changed from st.code to st.text
                    except Exception as e:
                        st.error("Decryption failed: " + str(e))
                else:
                    st.warning("You need to generate your keys and certificate first.")
        
        db_session.close()

if __name__ == "__main__":
    main()