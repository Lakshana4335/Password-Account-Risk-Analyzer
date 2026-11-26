import streamlit as st
import re
import matplotlib.pyplot as plt
from pathlib import Path
import secrets
import string

# Page settings
st.set_page_config(
    page_title="Password Risk Analyzer",
    page_icon="🔐",
    layout="centered"
)

# Project heading
st.title("🔐 Password & Account Risk Analyzer")

st.write(
    "Analyze password strength and account security "
    "using simple cybersecurity rules."
)

st.warning(
    "Use only sample test passwords. Never enter your "
    "real account password."
)

# Strong Password Generator

def generate_password(length):
    characters = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]

    password += [
        secrets.choice(characters)
        for _ in range(length - 4)
    ]

    secrets.SystemRandom().shuffle(password)

    return "".join(password)

# Load local common password list
def load_passwords():
    file_path = Path(__file__).parent / "common_passwords.txt"

    if not file_path.exists():
        return set()

    return {
        line.strip().lower()
        for line in file_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    }


# Password analysis function
def analyze_password(password, common_passwords):

    checks = {
        "Length (12 or more)": len(password) >= 12,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Number": bool(re.search(r"[0-9]", password)),
        "Special character": bool(
            re.search(r"[^A-Za-z0-9]", password)
        )
    }

    common = password.lower() in common_passwords

    repeated = bool(
        re.search(r"(.)\1{2,}", password)
    )

    sequences = [
        "1234", "2345", "3456",
        "abcd", "bcde", "cdef",
        "qwerty", "asdf"
    ]

    sequential = any(
        pattern in password.lower()
        for pattern in sequences
    )

    score = sum(checks.values())

    if common:
        score -= 2

    if repeated:
        score -= 1

    if sequential:
        score -= 1

    score = max(0, min(5, score))

    if common or score <= 2:
        strength = "Weak"
    elif score >= 4 and not repeated and not sequential:
        strength = "Strong"
    else:
        strength = "Moderate"

    return {
        "checks": checks,
        "common": common,
        "repeated": repeated,
        "sequential": sequential,
        "score": score,
        "strength": strength
    }

# Advanced Security Score

def calculate_security_score(result, mfa, reuse, recovery):

    # Password score (maximum 40)
    password_score = sum(
        result["checks"].values()
    ) * 8

    # Reduce score for weak patterns
    if result["common"]:
        password_score -= 12

    if result["repeated"]:
        password_score -= 6

    if result["sequential"]:
        password_score -= 6

    password_score = max(0, min(40, password_score))

    # Account security score
    mfa_score = 30 if mfa else 0
    unique_score = 20 if not reuse else 0
    recovery_score = 10 if recovery else 0

    total_score = (
        password_score +
        mfa_score +
        unique_score +
        recovery_score
    )

    return {
        "total": total_score,
        "password": password_score,
        "mfa": mfa_score,
        "unique": unique_score,
        "recovery": recovery_score
    }

# Strong Password Generator UI

st.subheader("1. Strong Password Generator")

password_length = st.slider(
    "Select Password Length",
    min_value=12,
    max_value=32,
    value=16
)

if st.button("Generate Strong Password"):
    st.session_state.generated_password = (
        generate_password(password_length)
    )

if st.session_state.get("generated_password"):
    st.code(st.session_state.generated_password)
    st.caption("Save it securely. Do not share your password.")

# User password input
st.subheader("1. Password Strength Analysis")

password = st.text_input(
    "Enter a sample test password",
    type="password"
)

# Account security checklist
st.subheader("2. Account Security Assessment")

mfa = st.checkbox("Multi-Factor Authentication (MFA) is enabled")

reuse = st.checkbox("I reuse this password on other accounts")

recovery = st.checkbox(
    "My account recovery email/phone is secure and up to date"
)

# Analyze button
if st.button("Analyze Security"):

    if not password:
        st.error("Please enter a sample password.")

    else:
        common_passwords = load_passwords()

        result = analyze_password(
            password,
            common_passwords
        )

        st.divider()

        # Password results
        st.subheader("3. Password Analysis Results")

        st.metric(
            "Password Strength",
            result["strength"]
        )

        st.write(
            "Strength Score:",
            str(result["score"]) + " / 5"
        )

        st.write("Password checks:")

        for name, passed in result["checks"].items():
            if passed:
                st.success(name + " - Passed")
            else:
                st.error(name + " - Not Passed")

        # Weak pattern results
        st.subheader("4. Weak Pattern Detection")

        if result["common"]:
            st.error("Common weak password detected.")

        if result["repeated"]:
            st.warning("Repeated characters detected.")

        if result["sequential"]:
            st.warning("Predictable sequence detected.")

        if not any([
            result["common"],
            result["repeated"],
            result["sequential"]
        ]):
            st.success("No listed weak patterns detected.")

        # Account risk calculation
        st.subheader("5. Account Risk Assessment")

        risk = 0

        if result["strength"] == "Weak":
            risk += 2
        elif result["strength"] == "Moderate":
            risk += 1

        if not mfa:
            risk += 2

        if reuse:
            risk += 2

        if not recovery:
            risk += 1

        if risk <= 1:
            risk_level = "Low"
        elif risk <= 3:
            risk_level = "Medium"
        else:
            risk_level = "High"

        st.metric("Account Risk Level", risk_level)
    
        # Advanced Security Score Display

        st.subheader("Advanced Security Score")

        security = calculate_security_score(
            result, mfa, reuse, recovery
        )

        st.metric(
            "Overall Security Score",
            str(security["total"]) + " / 100"
        )

        st.progress(security["total"] / 100)

        st.write("Security Score Breakdown")

        st.write(
            "Password Strength:",
            security["password"], "/ 40"
        )

        st.write("MFA Protection:", security["mfa"], "/ 30")

        st.write(
            "Password Uniqueness:",
            security["unique"], "/ 20"
        )

        st.write(
            "Recovery Protection:",
            security["recovery"], "/ 10"
        )

        if security["total"] >= 80:
            st.success("Good Security Level")

        elif security["total"] >= 50:
            st.warning("Moderate Security Level")

        else:
            st.error("Poor Security Level")


        # Recommendations
        st.subheader("6. Security Recommendations")

        recommendations = []

        if not result["checks"]["Length (12 or more)"]:
            recommendations.append(
                "Use a longer password."
            )

        if not result["checks"]["Uppercase letter"]:
            recommendations.append(
                "Include uppercase letters."
            )

        if not result["checks"]["Lowercase letter"]:
            recommendations.append(
                "Include lowercase letters."
            )

        if not result["checks"]["Number"]:
            recommendations.append(
                "Include numbers."
            )

        if not result["checks"]["Special character"]:
            recommendations.append(
                "Include special characters."
            )

        if result["common"]:
            recommendations.append(
                "Avoid common and predictable passwords."
            )

        if result["repeated"]:
            recommendations.append(
                "Avoid repeated character patterns."
            )

        if result["sequential"]:
            recommendations.append(
                "Avoid sequential character patterns."
            )

        if not mfa:
            recommendations.append(
                "Enable Multi-Factor Authentication."
            )

        if reuse:
            recommendations.append(
                "Use a unique password for every account."
            )

        if not recovery:
            recommendations.append(
                "Secure and update your recovery methods."
            )

        if recommendations:
            for item in recommendations:
                st.write("⚠️", item)
        else:
            st.success(
                "No improvements identified by these basic rules."
            )

        # Password visualization
        st.subheader("7. Password Security Chart")

        labels = list(result["checks"].keys())

        values = [
            int(value)
            for value in result["checks"].values()
        ]

        fig, ax = plt.subplots()

        ax.bar(labels, values)

        ax.set_ylim(0, 1.2)

        ax.set_ylabel("Result (1 = Pass, 0 = Fail)")

        ax.set_title("Password Security Checks")

        plt.xticks(rotation=25, ha="right")

        plt.tight_layout()

        st.pyplot(fig)

        plt.close(fig)

        st.info(
            "This is an educational rule-based assessment. "
            "It cannot guarantee account security."
        )