
import os
import time
import secrets
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import streamlit as st
from twilio.rest import Client


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="PragyanAI - OTP Verification",
    page_icon="🔐",
    layout="centered"
)


# --------------------------------------------------
# SECRETS CONFIGURATION
# Supports Streamlit Cloud secrets and environment
# variables for local development.
# --------------------------------------------------

def get_secret(key, default=""):
    try:
        value = st.secrets.get(key, default)
        if value:
            return str(value)
    except Exception:
        pass

    return os.getenv(key, default)


EMAIL_ADDRESS = get_secret("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = get_secret("EMAIL_APP_PASSWORD")

TWILIO_ACCOUNT_SID = get_secret("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = get_secret("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SERVICE_SID = get_secret(
    "TWILIO_VERIFY_SERVICE_SID"
)

OTP_EXPIRY = 300  # 5 minutes


# --------------------------------------------------
# SESSION STATE
# Each browser session maintains its own email OTP.
# --------------------------------------------------

defaults = {
    "email_otp": None,
    "email_otp_time": None,
    "email_otp_address": None,
    "email_verified": False,
    "verified_email_address": None,
    "phone_verified": False,
    "verified_phone_number": None,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def generate_otp():
    """Generate a cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(900000) + 100000}"


def get_twilio_client():
    """Create a Twilio client when credentials exist."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        raise ValueError(
            "Twilio credentials are missing. "
            "Configure your Streamlit secrets."
        )

    return Client(
        TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN
    )


def send_email_otp(recipient, otp):
    """Send an OTP through Gmail SMTP."""

    if not EMAIL_ADDRESS or not EMAIL_APP_PASSWORD:
        raise ValueError(
            "Email credentials are missing. "
            "Configure EMAIL_ADDRESS and EMAIL_APP_PASSWORD."
        )

    message = MIMEMultipart()
    message["From"] = EMAIL_ADDRESS
    message["To"] = recipient
    message["Subject"] = "Your PragyanAI Verification OTP"

    body = f"""
Hello,

Your OTP for email verification is:

{otp}

This OTP is valid for 5 minutes.
Please do not share this OTP with anyone.

Regards,
PragyanAI
"""

    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
        server.sendmail(
            EMAIL_ADDRESS,
            recipient,
            message.as_string()
        )


def send_email(email):
    """Validate email and send a new OTP."""

    email = email.strip().lower()

    if not email or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return "❌ Please enter a valid email address.", "error"

    if not EMAIL_ADDRESS or not EMAIL_APP_PASSWORD:
        return (
            "❌ Email credentials are not configured.",
            "error"
        )

    otp = generate_otp()

    try:
        send_email_otp(email, otp)

        st.session_state.email_otp = otp
        st.session_state.email_otp_time = time.time()
        st.session_state.email_otp_address = email
        st.session_state.email_verified = False
        st.session_state.verified_email_address = None

        return "✅ Email OTP sent successfully.", "success"

    except Exception:
        # Do not expose credentials or SMTP error details.
        st.session_state.email_otp = None
        st.session_state.email_otp_time = None
        st.session_state.email_otp_address = None

        return (
            "❌ Email sending failed. Check your Gmail "
            "App Password and SMTP configuration.",
            "error"
        )


def verify_email(email, entered_otp):
    """Verify an email OTP and enforce its expiry."""

    email = email.strip().lower()
    entered_otp = entered_otp.strip()

    if not email:
        return "❌ Please enter your email address.", "error"

    if not entered_otp:
        return "❌ Please enter the OTP.", "error"

    if not entered_otp.isdigit() or len(entered_otp) != 6:
        return "❌ Enter a valid 6-digit OTP.", "error"

    if st.session_state.email_otp is None:
        return "❌ Please request a new OTP.", "error"

    if email != st.session_state.email_otp_address:
        return (
            "❌ This OTP belongs to a different email address.",
            "error"
        )

    elapsed = time.time() - st.session_state.email_otp_time

    if elapsed > OTP_EXPIRY:
        st.session_state.email_otp = None
        st.session_state.email_otp_time = None
        return (
            "❌ OTP expired. Please request a new OTP.",
            "error"
        )

    if secrets.compare_digest(
        entered_otp, st.session_state.email_otp
    ):
        st.session_state.email_verified = True
        st.session_state.verified_email_address = email
        st.session_state.email_otp = None
        st.session_state.email_otp_time = None

        return "✅ Email verified successfully!", "success"

    return "❌ Invalid OTP.", "error"


def send_phone_otp(phone):
    """Send an SMS verification through Twilio Verify."""

    phone = phone.strip()

    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return (
            "❌ Enter a valid international number, "
            "including country code (e.g. +919876543210).",
            "error"
        )

    if not TWILIO_VERIFY_SERVICE_SID:
        return (
            "❌ Twilio Verify Service SID is not configured.",
            "error"
        )

    try:
        client = get_twilio_client()

        verification = (
            client.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verifications.create(
                to=phone,
                channel="sms"
            )
        )

        st.session_state.phone_verified = False
        st.session_state.verified_phone_number = None

        return (
            f"✅ SMS OTP request submitted. Status: "
            f"{verification.status}",
            "success"
        )

    except Exception:
        return (
            "❌ SMS sending failed. Check your Twilio "
            "credentials, service SID, and account settings.",
            "error"
        )


def verify_phone_otp(phone, entered_otp):
    """Verify the SMS code using Twilio Verify."""

    phone = phone.strip()
    entered_otp = entered_otp.strip()

    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return "❌ Enter a valid phone number.", "error"

    if not re.fullmatch(r"\d{4,10}", entered_otp):
        return "❌ Enter the verification code.", "error"

    if not TWILIO_VERIFY_SERVICE_SID:
        return (
            "❌ Twilio Verify Service SID is not configured.",
            "error"
        )

    try:
        client = get_twilio_client()

        check = (
            client.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verification_checks.create(
                to=phone,
                code=entered_otp
            )
        )

        if check.status == "approved":
            st.session_state.phone_verified = True
            st.session_state.verified_phone_number = phone

            return (
                "✅ Phone number verified successfully!",
                "success"
            )

        return "❌ Invalid or expired OTP.", "error"

    except Exception:
        return (
            "❌ Verification failed. The code may have "
            "expired, or the Twilio request was rejected.",
            "error"
        )


# --------------------------------------------------
# USER INTERFACE
# --------------------------------------------------

st.title("🔐 PragyanAI OTP Verification System")

st.write(
    "Securely verify your email address and phone number "
    "using Python, Streamlit, Gmail SMTP, and Twilio."
)

st.info("Email OTPs expire after 5 minutes. Phone OTPs are managed by Twilio Verify.")

# EMAIL VERIFICATION

st.header("📧 Email Verification")

with st.form("email_send_form"):
    email = st.text_input(
        "Email Address",
        placeholder="example@gmail.com"
    )
    send_email_button = st.form_submit_button(
        "Send Email OTP",
        use_container_width=True
    )

if send_email_button:
    message, kind = send_email(email)
    if kind == "success":
        st.success(message)
    else:
        st.error(message)

with st.form("email_verify_form"):
    email_to_verify = st.text_input(
        "Email Address for Verification",
        placeholder="Enter the same email address"
    )
    email_otp_input = st.text_input(
        "Enter Email OTP",
        max_chars=6,
        placeholder="6-digit OTP"
    )
    verify_email_button = st.form_submit_button(
        "Verify Email",
        use_container_width=True
    )

if verify_email_button:
    message, kind = verify_email(
        email_to_verify,
        email_otp_input
    )
    if kind == "success":
        st.success(message)
    else:
        st.error(message)

if st.session_state.email_verified:
    st.caption(
        f"Verified email: "
        f"{st.session_state.verified_email_address}"
    )


st.divider()

# PHONE VERIFICATION

st.header("📱 Phone Verification")

with st.form("phone_send_form"):
    phone = st.text_input(
        "Phone Number",
        placeholder="+919876543210",
        help="Use international format, including the + country code."
    )
    send_phone_button = st.form_submit_button(
        "Send SMS OTP",
        use_container_width=True
    )

if send_phone_button:
    message, kind = send_phone_otp(phone)
    if kind == "success":
        st.success(message)
    else:
        st.error(message)

with st.form("phone_verify_form"):
    phone_to_verify = st.text_input(
        "Phone Number for Verification",
        placeholder="Enter the same phone number"
    )
    phone_otp_input = st.text_input(
        "Enter SMS OTP",
        max_chars=10,
        placeholder="Enter the code received"
    )
    verify_phone_button = st.form_submit_button(
        "Verify Phone",
        use_container_width=True
    )

if verify_phone_button:
    message, kind = verify_phone_otp(
        phone_to_verify,
        phone_otp_input
    )
    if kind == "success":
        st.success(message)
    else:
        st.error(message)

if st.session_state.phone_verified:
    st.caption(
        f"Verified phone: "
        f"{st.session_state.verified_phone_number}"
    )

st.divider()

if (
    st.session_state.email_verified
    and st.session_state.phone_verified
):
    st.success("🎉 Both email and phone number are verified!")

st.caption("Developed as a PragyanAI Python project.")
