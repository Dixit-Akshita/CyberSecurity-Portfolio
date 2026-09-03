from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

# 🏠 HOME PAGE
@app.route('/')
def home():
    return render_template('index.html')


# 📄 PAGES
@app.route('/url')
def url_page():
    return render_template("url.html")

@app.route('/password')
def password_page():
    return render_template("password.html")

@app.route('/awareness')
def awareness():
    return render_template('awareness.html')


# ================================
# 🔥 API ROUTES
# ================================

@app.route('/check_url', methods=["POST"])
def check_url_api():
    url = request.form.get("url")

    result, suggestion = check_url(url)

    return jsonify({
        "result": result,
        "suggestion": suggestion
    })


@app.route('/check_password', methods=["POST"])
def check_password_api():
    password = request.form.get("password")

    result, suggestion = check_password(password)

    return jsonify({
        "result": result,
        "suggestion": suggestion
    })


# ================================
# 🔐 PASSWORD LOGIC
# ================================
def check_password(password):
    score = 0

    if len(password) >= 8:
        score += 1

    if any(char.isupper() for char in password):
        score += 1

    if any(char.islower() for char in password):
        score += 1

    if any(char.isdigit() for char in password):
        score += 1

    if any(char in "!@#$%^&*()_+" for char in password):
        score += 2

    # 🔥 weak patterns
    weak_patterns = ["123", "abc", "password", "qwerty"]
    if any(p in password.lower() for p in weak_patterns):
        score -= 2

    if score <= 2:
        return "Weak", "Use mix of uppercase, lowercase, numbers & symbols."
    elif score <= 5:
        return "Medium", "Add more complexity (symbols, longer length)."
    else:
        return "Strong", "Excellent password 🔐"


# ================================
# 🔗 URL LOGIC (PRO VERSION)
# ================================
def check_url(url):
    score = 0

    if not url:
        return "Invalid", "Please enter a valid URL"

    # Auto add https
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]

    # IP Address
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 3

    # Too many subdomains
    if domain.count(".") > 2:
        score += 2

    # Suspicious keywords
    suspicious_words = [
        "login", "verify", "update", "bank",
        "secure", "account", "signin",
        "wallet", "payment"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 2

    # Special characters
    special_chars = ["@", "%", "_", "~", "!", "$", "^", "&", "*"]

    for ch in special_chars:
        if ch in url:
            score += 2

    # Hyphen detection
    if "-" in domain:
        score += 2

    # Multiple hyphens
    if domain.count("-") >= 2:
        score += 3

    # Numbers in domain
    if re.search(r"\d", domain):
        score += 2

    # HTTP instead of HTTPS
    if url.startswith("http://"):
        score += 1

    # Long URL
    if len(url) > 80:
        score += 1

    # Lookalike domains
    legit_domains = [
        "google.com",
        "facebook.com",
        "amazon.com",
        "instagram.com",
        "twitter.com",
        "bankofindia.co.in"
    ]

    normalized = (
        domain.replace("0", "o")
              .replace("1", "l")
              .replace("3", "e")
              .replace("5", "s")
    )

    clean_domain = normalized.replace("-", "")

    for legit in legit_domains:
        legit_name = legit.split(".")[0]

        if legit_name in clean_domain and domain != legit:
            return (
                "Danger",
                f"Possible fake version of {legit} detected 🚨"
            )

    # Final Result
    if score == 0:
        return "Safe", "Looks safe 👍 but always stay alert."

    elif score <= 3:
        return "Suspicious", "This URL contains suspicious patterns ⚠️"

    else:
        return "Danger", "High phishing risk 🚨 Avoid visiting this website."
    app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)

# ▶️ RUN
if __name__ == '__main__':
    app.run(debug=True)