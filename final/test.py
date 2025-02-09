from flask import Flask, jsonify, render_template, request
import requests
import psycopg2
import os
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()


DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
NVD_API_URL = os.getenv("NVD_API_URL")


def connect_db():
    """Helper function to connect to the PostgreSQL database."""
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)


def create_db():
    """Create the PostgreSQL tables to store CVE summary data."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            identifier TEXT,
            description TEXT,
            published_date TEXT,
            last_modified_date TEXT,
            status TEXT CHECK(status IN ('analysed', 'modified', 'rejected'))
        )
    ''')
    conn.commit()
    conn.close()

def fetch_and_store_cve_data(offset=0, limit=20):
    """
    Fetch CVE data from the NVD API and store/update it in the PostgreSQL database.
    The description is extracted from:
      description = cve_data["cve"].get("descriptions", [{"value": ""}])[0]["value"]
    """
    url = f"{NVD_API_URL}?startIndex={offset}&resultsPerPage={limit}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        conn = connect_db()
        cursor = conn.cursor()
        for cve_data in cve_items:
            # Extract summary fields
            cve_id = cve_data["cve"].get("id", "")
            identifier = cve_data["cve"].get("sourceIdentifier", "N/A")
            description = cve_data["cve"].get("descriptions", [{"value": ""}])[0]["value"]
            published_date = cve_data["cve"].get("published", "")[:10]  # yyyy-mm-dd
            last_modified_date = cve_data["cve"].get("lastModified", "")[:10]
            # Determine status dynamically (here using a simple logic)
            if last_modified_date and last_modified_date != published_date:
                status = "modified"
            elif published_date:
                status = "analysed"
            else:
                status = "rejected"

            cursor.execute('''
                INSERT INTO cves (cve_id, identifier, description, published_date, last_modified_date, status)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    identifier = EXCLUDED.identifier,
                    description = EXCLUDED.description,
                    published_date = EXCLUDED.published_date,
                    last_modified_date = EXCLUDED.last_modified_date,
                    status = EXCLUDED.status
            ''', (cve_id, identifier, description, published_date, last_modified_date, status))
        conn.commit()
        conn.close()
        return {"status": "Data updated successfully"}
    return {"error": "Failed to fetch CVE data"}

@app.route("/")
def home():
    """
    Home page:
      - Retrieves a paginated list of CVEs from the database.
      - Supports a dropdown to select results per page (default 10).
      - Pagination controls (Previous/Next and individual page links).
    """
    # Get query parameters; default page = 1, results per page = 10.
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 10))
    offset = (page - 1) * per_page

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves")
    total_records = cursor.fetchone()[0]
    total_pages = (total_records + per_page - 1) // per_page

    cursor.execute("""
        SELECT cve_id, identifier, published_date, last_modified_date, status
        FROM cves
        ORDER BY published_date DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    rows = cursor.fetchall()
    conn.close()

    cve_data = [
        {
            "cve_id": row[0],
            "identifier": row[1],
            "published_date": row[2],
            "last_modified_date": row[3],
            "status": row[4]
        } for row in rows
    ]

    return render_template("index.html", cves=cve_data,
                           current_page=page, total_pages=total_pages, per_page=per_page)

@app.route("/cves/<string:cve_id>")
def cve_details(cve_id):
    """
    Detailed CVE page:
      - When a user clicks on a CVE ID from the home page, this route is called.
      - It makes an API call to fetch detailed information for that CVE.
      - The description is extracted using:
            description = cve_data["cve"].get("descriptions", [{"value": ""}])[0]["value"]
      - Also fetches CVSS metrics like severity, base score, vector string, etc.
    """
    # Use query parameter endpoint; adjust URL per NVD API requirements.
    details_url = f"{NVD_API_URL}?cveId={cve_id}"
    response = requests.get(details_url)
    if response.status_code == 200:
        data = response.json()
        try:
            # Get the first vulnerability from the response
            cve_item = data.get("vulnerabilities", [])[0]["cve"]
        except (IndexError, KeyError):
            return jsonify({"error": "No CVE details found for the provided ID"}), 404

        details = {
            "cve_id": cve_item.get("id", cve_id),
            "description": cve_item.get("descriptions", [{"value": ""}])[0]["value"],
            # Using CVSS v3 if available, else fallback to v2 metrics:
            "severity": cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("baseSeverity", 
                          cve_item.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown")),
            "base_score": cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("baseScore", 
                           cve_item.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseScore", "N/A")),
            "vector_string": cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("vectorString", 
                              cve_item.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("vectorString", "N/A")),
            "exploitability_score": cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("exploitabilityScore", 
                                    cve_item.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("exploitabilityScore", "N/A")),
            "impact_score": cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("impactScore", 
                             cve_item.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("impactScore", "N/A")),
            "cpe": "Not provided"
        }
        # If CPE details are available in configurations, try to extract them:
        try:
            nodes = cve_item.get("configurations", {}).get("nodes", [])
            if nodes:
                cpe_matches = nodes[0].get("cpeMatch", [])
                if cpe_matches:
                    details["cpe"] = cpe_matches[0].get("cpe23Uri", "N/A")
        except Exception:
            details["cpe"] = "N/A"

        return render_template("cve_details.html", details=details)
    return jsonify({"error": "Failed to fetch CVE details"}), response.status_code

if __name__ == "__main__":
    create_db()
    # Uncomment the next line if you want to fetch initial CVE data on startup.
    fetch_and_store_cve_data()  
    app.run(debug=True)
