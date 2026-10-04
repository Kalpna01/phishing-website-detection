from flask import Flask, request, render_template, session
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
from urllib.parse import urlparse
import re

app = Flask(__name__)

app.secret_key = "phishing-detector-secret-key"

# Load model
model = tf.keras.models.load_model("phishing_model.h5")

# Load tokenizer
with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 150

SAFE_DOMAINS = [
    "google.com",
    "wikipedia.org",
    "github.com",
    "amazon.in",
    "youtube.com",
    "microsoft.com"
    "nietcloud.niet.co.in"
]


def is_trusted_domain(hostname):
    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname in SAFE_DOMAINS


def analyze_url(url):

    url_lower = url.lower()

    if not url_lower.startswith(("http://", "https://")):
        parse_url = "http://" + url_lower
    else:
        parse_url = url_lower

    parsed_url = urlparse(parse_url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""

    indicators = []
    positive_indicators = []

    # HTTPS
    if parsed_url.scheme == "https":
        positive_indicators.append(
            "HTTPS is being used."
        )
    else:
        indicators.append(
            "The URL is not using HTTPS."
        )

    # Suspicious keywords
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "update",
        "secure",
        "confirm",
        "bank",
        "wallet",
        "payment",
        "credential",
        "recover",
        "authenticate"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    for word in found_words[:6]:
        indicators.append(
            f"Contains suspicious keyword: '{word}'."
        )

    # URL length
    url_length = len(url)

    if url_length > 100:
        indicators.append(
            f"URL is unusually long ({url_length} characters)."
        )
    else:
        positive_indicators.append(
            f"URL length is {url_length} characters."
        )

    # IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    is_ip = bool(re.match(ip_pattern, hostname))

    if is_ip:
        indicators.append(
            "An IP address is being used instead of a normal domain name."
        )
    else:
        positive_indicators.append(
            "No direct IP address is being used as the domain."
        )

    # @ symbol
    if "@" in url:
        indicators.append(
            "The URL contains an '@' symbol."
        )
    else:
        positive_indicators.append(
            "No '@' symbol was detected."
        )

    # Hyphens
    hyphen_count = url.count("-")

    if hyphen_count >= 3:
        indicators.append(
            f"The URL contains many hyphens ({hyphen_count})."
        )
    else:
        positive_indicators.append(
            f"Hyphen count: {hyphen_count}."
        )

    # Subdomains
    domain_parts = hostname.split(".") if hostname else []

    subdomain_count = max(len(domain_parts) - 2, 0)

    if len(domain_parts) >= 4:
        indicators.append(
            "The domain contains several subdomains."
        )
    else:
        positive_indicators.append(
            "Domain structure appears relatively simple."
        )

    # Special characters
    special_count = len(
        re.findall(r"[!#$%^&*()_+=]", url)
    )

    if special_count >= 3:
        indicators.append(
            f"Several special characters were detected ({special_count})."
        )
    else:
        positive_indicators.append(
            f"Special character count: {special_count}."
        )

    # Path depth
    path_depth = path.count("/")

    if path_depth >= 4:
        indicators.append(
            "The URL contains a deeply nested path."
        )

    details = {
        "protocol": parsed_url.scheme.upper(),
        "domain": hostname if hostname else "Not detected",
        "path": path if path else "/",
        "length": url_length,
        "hyphens": hyphen_count,
        "subdomains": subdomain_count,
        "https": parsed_url.scheme == "https",
        "ip_address": is_ip
    }

    return indicators, positive_indicators, details


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"].strip()

    url_clean = url.lower()

    # Parse domain
    if not url_clean.startswith(("http://", "https://")):
        parse_url = "http://" + url_clean
    else:
        parse_url = url_clean

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    # URL analysis
    indicators, positive_indicators, details = analyze_url(url)

    # Trusted domain
    if is_trusted_domain(hostname):

        result = "SAFE / LEGITIMATE"

        confidence = "100.00%"

        is_phishing = False

        risk_level = "LOW"

        explanation = (
            "This URL belongs to a domain included in the "
            "application's trusted-domain list. The application "
            "recognizes this domain as trusted."
        )

        session["analysis"] = {
            "url": url,
            "result": result,
            "confidence": confidence,
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "explanation": explanation,
            "indicators": [],
            "positive_indicators": positive_indicators,
            "details": details
        }

        return render_template(
            "index.html",
            url=url,
            result=result,
            confidence=confidence,
            is_phishing=is_phishing,
            risk_level=risk_level
        )

    # CNN + LSTM prediction
    seq = tokenizer.texts_to_sequences([url_clean])

    padded = pad_sequences(
        seq,
        maxlen=MAX_LEN,
        padding="post",
        truncating="post"
    )

    prob = model.predict(
        padded,
        verbose=0
    )[0][0]

    # Prediction
    if prob >= 0.65:

        result = "PHISHING / MALICIOUS WEBSITE DETECTED"

        confidence = f"{prob * 100:.2f}%"

        is_phishing = True

        risk_level = "HIGH"

        explanation = (
            "The CNN + LSTM model classified this URL as "
            "potentially phishing. Additional URL analysis "
            "also identified the characteristics shown below. "
            "These characteristics provide additional context "
            "and are not the exact internal reasoning of the "
            "neural network."
        )

    else:

        result = "SAFE / LEGITIMATE WEBSITE"

        confidence = f"{(1 - prob) * 100:.2f}%"

        is_phishing = False

        risk_level = "LOW"

        explanation = (
            "The CNN + LSTM model classified this URL as "
            "likely safe. The additional URL analysis did not "
            "identify strong suspicious characteristics. "
            "However, this result cannot guarantee that the "
            "website is completely safe."
        )

    # Save analysis
    session["analysis"] = {
        "url": url,
        "result": result,
        "confidence": confidence,
        "is_phishing": is_phishing,
        "risk_level": risk_level,
        "explanation": explanation,
        "indicators": indicators,
        "positive_indicators": positive_indicators,
        "details": details
    }

    return render_template(
        "index.html",
        url=url,
        result=result,
        confidence=confidence,
        is_phishing=is_phishing,
        risk_level=risk_level
    )


@app.route("/analysis")
def analysis():

    analysis_data = session.get("analysis")

    if not analysis_data:
        return render_template(
            "analysis.html",
            no_data=True
        )

    return render_template(
        "analysis.html",
        data=analysis_data
    )


if __name__ == "__main__":
    app.run(
        debug=True,
        port=5000
    )
