# CVE Management System

## Description
The CVE Management System is a web application designed to provide users with comprehensive information about Common Vulnerabilities and Exposures (CVEs). This application allows users to view a list of CVEs, filter them based on various criteria, and access detailed information about each vulnerability. The system is built using Flask, a lightweight web framework for Python, and utilizes a MySQL database to store and manage CVE data.

## Features
- **View CVE List**: Users can view a paginated list of CVEs with essential details.
- **Filter Options**: Users can filter the CVE list by CVE ID, CVSS score, and modification date.
- **Detailed CVE Information**: Users can click on a CVE to view detailed information, including metrics and vulnerabilities.
- **API Endpoints**: The application provides RESTful API endpoints for accessing CVE data programmatically.
- **Background Synchronization**: The application continuously syncs CVE data from an external source to keep the database up-to-date.

## Technologies Used
- **Python**: The programming language used for backend development.
- **Flask**: A lightweight web framework for building web applications.
- **MySQL**: A relational database management system used to store CVE data.
- **Requests**: A Python library for making HTTP requests to fetch CVE data.
- **Bootstrap**: A front-end framework for developing responsive web applications.
- **dotenv**: A library for loading environment variables from a `.env` file.

## Installation
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Securin Assignment Solution
   ```

2. **Install the required packages**:
   Make sure you have Python and pip installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your environment variables**:
   Create a `.env` file in the project root and add your database configuration:
   ```
   DB_HOST=<your_db_host>
   DB_USER=<your_db_user>
   DB_PASSWORD=<your_db_password>
   DB_NAME=<your_db_name>
   ```

## Usage
1. **Run the application**:
   Start the Flask application by running:
   ```bash
   python app.py
   ```

2. **Access the application**:
   Open your web browser and navigate to `http://127.0.0.1:5000` to access the CVE Management System.

3. **Explore the features**:
   - Use the filtering options to narrow down the CVE list.
   - Click on a CVE ID to view detailed information about that vulnerability.

## API Endpoints
The application provides the following API endpoints:

- **List CVEs**: `GET /cves/list`
  - Retrieves a paginated list of CVEs with filtering options.
  
- **Get CVE by ID**: `GET /cves/<cve_id>`
  - Retrieves detailed information about a specific CVE by its ID.

- **Filter by Year**: `GET /api/cves/year/<int:year>`
  - Retrieves CVEs that were published in a specific year.

- **Filter by CVSS Score**: `GET /api/cves/score/<float:score>`
  - Retrieves CVEs with a CVSS score greater than or equal to the specified score.

- **Filter by Modification Date**: `GET /api/cves/modified/<int:days>`
  - Retrieves CVEs that have been modified in the last specified number of days.

## Contributing
Contributions are welcome! If you would like to contribute to this project, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and open a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
