import requests
import mysql.connector
from flask import Flask, jsonify, request, render_template, redirect, url_for
from datetime import datetime, timedelta
from dotenv import load_dotenv
import threading
import time
import os

load_dotenv()
app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Abilash@2003',
        database='coredata'
    )

def fetch_cves(start_index=0, results_per_page=10, retries=5, delay=5):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }

    for attempt in range(retries):
        try:
            response = requests.get(base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                print("Fetched CVEs:")
                return data
            else:
                print(f"Error fetching CVEs: {response.status_code}")
                return {}
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVEs: {e}")

        print(f"Retrying in {delay} seconds...")
        time.sleep(delay)

    print("Failed to fetch CVEs after multiple attempts.")
    return {}


# Update the sync_cves function to handle the structure of the response
def sync_cves():
    start_index = 0
    results_per_page = 10
    while True:
        print("Fetching CVEs...")
        cve_data = fetch_cves(start_index, results_per_page)

        # Ensure that 'vulnerabilities' key exists and it's not empty
        vulnerabilities = cve_data.get('vulnerabilities', [])

        if not vulnerabilities:
            print("No vulnerabilities found. Please check the response structure.")
            break

        # Loop through the list of CVE items
        for cve_item in vulnerabilities:
            cleaned_data = clean_data(cve_item)
            if cleaned_data:
                store_cve(cleaned_data)

        start_index += results_per_page
        time.sleep(10)  # Sleep for a while before the next fetch cycle

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_details (
        cve_id VARCHAR(255) PRIMARY KEY,
        description TEXT NOT NULL,
        published_date DATETIME NOT NULL,
        modified_date DATETIME NOT NULL,
        cvss_score FLOAT,
        cvss_v2_score FLOAT,
        cvss_v3_score FLOAT,
        weaknesses TEXT,
        configurations TEXT,
        reference_links TEXT,
        year INT NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'new'
    );
    ''')
    conn.commit()
    cursor.close()
    conn.close()

def store_cve(cve_data):
    conn = get_db_connection()
    cursor = conn.cursor()

    insert_query = '''
    INSERT INTO cve_details (
        cve_id, description, published_date, modified_date, cvss_score, cvss_v2_score, cvss_v3_score,
        weaknesses, configurations, reference_links, year, status
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        description=VALUES(description), modified_date=VALUES(modified_date),
        cvss_score=VALUES(cvss_score), cvss_v2_score=VALUES(cvss_v2_score), cvss_v3_score=VALUES(cvss_v3_score),
        weaknesses=VALUES(weaknesses), configurations=VALUES(configurations), reference_links=VALUES(reference_links),
        status=VALUES(status);
    '''

    try:
        cursor.execute(insert_query, tuple(cve_data.values()))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    finally:
        cursor.close()
        conn.close()

def clean_data(cve_item):
    try:
        cve = cve_item.get('cve', {})
        cve_id = cve.get('id')
        if not cve_id:
            return None
        descriptions = cve.get('descriptions', [{}])[0].get('value', 'No description available')

        try:
            published_date = datetime.strptime(cve.get('published', '1970-01-01T00:00:00.000'), "%Y-%m-%dT%H:%M:%S.%f")
            modified_date = datetime.strptime(cve.get('lastModified', '1970-01-01T00:00:00.000'), "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            return None

        year = int(cve_id.split('-')[1]) if '-' in cve_id else 1970
        status = cve.get('vulnStatus', 'new')

        metrics = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {})
        cvss_v2_score = metrics.get('baseScore')
        cvss_v3_score = cve.get('metrics', {}).get('cvssMetricV3', [{}])[0].get('cvssData', {}).get('baseScore')

        weaknesses = ', '.join([w.get('description', [{}])[0].get('value', 'Unknown') for w in cve.get('weaknesses', [])])
        configurations = ', '.join([c.get('nodes', [{}])[0].get('operator', 'Unknown') for c in cve.get('configurations', [])])
        references = ', '.join([r.get('url', '') for r in cve.get('references', [])])

        return {
            "cve_id": cve_id, "description": descriptions, "published_date": published_date, "modified_date": modified_date,
            "cvss_score": cvss_v2_score or cvss_v3_score, "cvss_v2_score": cvss_v2_score, "cvss_v3_score": cvss_v3_score,
            "weaknesses": weaknesses, "configurations": configurations, "reference_links": references, "year": year, "status": status
        }
    except Exception as e:
        print(f"Skipping CVE due to error: {e}")
        return None

# Start sync in a background thread
def start_sync_thread():
    sync_thread = threading.Thread(target=sync_cves)
    sync_thread.daemon = True
    sync_thread.start()

@app.route('/')
def home():
    return redirect(url_for('list_cves', page=1, resultsPerPage=10))

# Route to list CVEs in a table with pagination
@app.route('/cves/list', methods=['GET'])
def list_cves():
    # Pagination and Results per Page handling
    page = int(request.args.get('page', 1))
    results_per_page = int(request.args.get('resultsPerPage', 10))  # Default to 10 results per page
    sort_order = request.args.get('sort', 'published_date')  # Default to sorting by published_date
    sort_direction = request.args.get('direction', 'ASC')  # Default to ascending order

    # Validate sort_order and sort_direction to prevent SQL injection
    valid_sort_columns = ['cve_id', 'published_date', 'modified_date', 'status']
    valid_sort_directions = ['ASC', 'DESC']

    if sort_order not in valid_sort_columns:
        sort_order = 'published_date'  # Default to published_date if invalid
    if sort_direction not in valid_sort_directions:
        sort_direction = 'ASC'  # Default to ASC if invalid

    start_index = (page - 1) * results_per_page

    # Get filter parameters from the request
    cve_id_filter = request.args.get('cve_id', None)
    cvss_score_filter = request.args.get('cvss_score', None)
    modified_date_filter = request.args.get('modified_date', None)

    # Build the WHERE clause dynamically
    where_clauses = []
    params = {}

    if cve_id_filter and cve_id_filter.lower() != 'none':  # Check if cve_id_filter is not None or "None"
        where_clauses.append("cve_id = %(cve_id)s")
        params['cve_id'] = cve_id_filter

    if cvss_score_filter and cvss_score_filter.lower() != 'none':  # Check if cvss_score_filter is not None or "None"
        where_clauses.append("cvss_score >= %(cvss_score)s")
        try:
            params['cvss_score'] = float(cvss_score_filter)
        except ValueError:
            # Handle invalid CVSS score input (e.g., log an error, display a message to the user)
            params['cvss_score'] = 0.0  # Default value

    if modified_date_filter and modified_date_filter.lower() != 'none':  # Check if modified_date_filter is not None or "None"
        where_clauses.append("modified_date >= %(modified_date)s")
        try:
            params['modified_date'] = datetime.strptime(modified_date_filter, '%Y-%m-%d')  # Use the correct format
        except ValueError:
            # Handle invalid date input
            params['modified_date'] = datetime.min  # Default to the earliest date

    where_clause = ""
    if where_clauses:
        where_clause = "WHERE " + " AND ".join(where_clauses)

    # Query to get total records count with filtering
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    count_query = f"SELECT COUNT(*) FROM cve_details {where_clause}"
    cursor.execute(count_query, params)
    total_records = cursor.fetchone()['COUNT(*)']

    # Query to fetch CVEs with pagination, sorting, and filtering
    select_query = f"""
        SELECT cve_id, description, published_date, modified_date, cvss_v2_score, status, year
        FROM cve_details
        {where_clause}
        ORDER BY {sort_order} {sort_direction}
        LIMIT {results_per_page} OFFSET {start_index}
    """
    cursor.execute(select_query, params)
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('cve_list.html',
                           cves=cves,
                           page=page,
                           results_per_page=results_per_page,
                           total_records=total_records,
                           sort_order=sort_order,
                           sort_direction=sort_direction,
                           cve_id_filter=cve_id_filter,
                           cvss_score_filter=cvss_score_filter,
                           modified_date_filter=modified_date_filter)

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cve_id = %s", (cve_id,))
    cve = cursor.fetchone()
    cursor.close()
    conn.close()

    if cve:
        return render_template('cve_details.html', cve=cve)
    else:
        return jsonify({"error": "CVE not found"}), 404

# API to filter CVEs by Year
@app.route('/api/cves/year/<int:year>', methods=['GET'])
def get_cves_by_year(year):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE year = %s", (year,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

# API to filter CVEs by CVSS score
@app.route('/api/cves/score/<float:score>', methods=['GET'])
def get_cves_by_score(score):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cvss_score >= %s", (score,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

# API to filter CVEs modified in the last N days
@app.route('/api/cves/modified/<int:days>', methods=['GET'])
def get_cves_modified(days):
    cutoff_date = datetime.now() - timedelta(days=days)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE modified_date >= %s", (cutoff_date,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

if __name__ == '__main__':
    # Ensure the table is created on startup
    create_table()
    # Start the background CVE synchronization thread
    start_sync_thread()
    app.run(debug=True)