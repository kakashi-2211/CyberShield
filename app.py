from flask import Flask, render_template, request
from urllib.parse import urlparse
import requests
import time

app = Flask(__name__)


# ============================================================
# URL VALIDATION
# ============================================================

def check_url(url):

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.netloc:
            return False

        if not parsed.hostname:
            return False

        return True

    except Exception:
        return False


# ============================================================
# WEBSITE SCANNER
# ============================================================

def scan_website(url):

    security_headers = {
        "Strict-Transport-Security": {
            "name": "HSTS",
            "description": "Helps enforce secure HTTPS connections.",
            "severity": "HIGH"
        },

        "Content-Security-Policy": {
            "name": "CSP",
            "description": "Helps protect against malicious scripts and content injection.",
            "severity": "HIGH"
        },

        "X-Content-Type-Options": {
            "name": "X-Content-Type-Options",
            "description": "Prevents browsers from incorrectly interpreting content types.",
            "severity": "MEDIUM"
        },

        "X-Frame-Options": {
            "name": "X-Frame-Options",
            "description": "Helps prevent clickjacking attacks.",
            "severity": "MEDIUM"
        },

        "Referrer-Policy": {
            "name": "Referrer-Policy",
            "description": "Controls how much referrer information is shared with other websites.",
            "severity": "LOW"
        },

        "Permissions-Policy": {
            "name": "Permissions-Policy",
            "description": "Controls access to browser features and capabilities.",
            "severity": "LOW"
        }
    }


    try:

        # ----------------------------------------------------
        # REQUEST START
        # ----------------------------------------------------

        start_time = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        end_time = time.perf_counter()


        # ----------------------------------------------------
        # RESPONSE TIME
        # ----------------------------------------------------

        response_time = round(
            end_time - start_time,
            3
        )


        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        https_enabled = response.url.startswith("https://")


        # ----------------------------------------------------
        # SECURITY HEADERS
        # ----------------------------------------------------

        headers = {}

        for header_name, info in security_headers.items():

            value = response.headers.get(header_name)

            headers[info["name"]] = {

                "present": value is not None,

                "value": value if value else "",

                "description": info["description"],

                "severity": info["severity"]

            }


        # ----------------------------------------------------
        # SECURITY SCORE
        # ----------------------------------------------------

        score = 0


        # HTTPS
        if https_enabled:
            score += 30


        # Successful HTTP response
        if 200 <= response.status_code < 300:
            score += 20


        # Security headers
        if headers["HSTS"]["present"]:
            score += 10

        if headers["CSP"]["present"]:
            score += 10

        if headers["X-Content-Type-Options"]["present"]:
            score += 10

        if headers["X-Frame-Options"]["present"]:
            score += 5

        if headers["Referrer-Policy"]["present"]:
            score += 5

        if headers["Permissions-Policy"]["present"]:
            score += 5


        # Response speed
        if response_time < 1:
            score += 5


        # ----------------------------------------------------
        # RATING
        # ----------------------------------------------------

        if score >= 90:

            rating = "Excellent"

        elif score >= 75:

            rating = "Good"

        elif score >= 50:

            rating = "Moderate"

        else:

            rating = "Needs Improvement"


        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        return {

            "success": True,

            "status_code": response.status_code,

            "final_url": response.url,

            "response_time": response_time,

            "https_enabled": https_enabled,

            "headers": headers,

            "score": score,

            "rating": rating,

            "message": "Website scan completed successfully."

        }


    # ========================================================
    # ERRORS
    # ========================================================

    except requests.exceptions.Timeout:

        return {

            "success": False,

            "message": "The website took too long to respond."

        }


    except requests.exceptions.SSLError:

        return {

            "success": False,

            "message": "SSL/TLS connection error."

        }


    except requests.exceptions.ConnectionError:

        return {

            "success": False,

            "message": "Could not connect to the website."

        }


    except requests.exceptions.RequestException as error:

        return {

            "success": False,

            "message": f"Request error: {error}"

        }


    except Exception as error:

        return {

            "success": False,

            "message": f"Unexpected error: {error}"

        }


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    website = ""


    if request.method == "POST":

        website = request.form.get(
            "website",
            ""
        ).strip()


        # Add HTTPS automatically if user forgot it
        if website and not website.startswith(
            ("http://", "https://")
        ):

            website = "https://" + website


        # Validate URL
        if not check_url(website):

            result = {

                "success": False,

                "message":
                    "Please enter a valid website URL."

            }

        else:

            result = scan_website(website)


    return render_template(
        "index.html",
        result=result,
        website=website
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )