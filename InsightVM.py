from base64 import b64encode
from datetime import datetime
import http.client
import json
import os
import ssl
import sys
from time import sleep
import uuid


class InsightVmApi:
    def __init__(self, url, username, password, verify_ssl):
        # Craft basic authentication
        auth = f"{username}:{password}"
        auth = b64encode(auth.encode('ascii')).decode()

        self.base_resource = "/api/3"
        self.headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': f"Basic {auth}"
        }
        self.conn = http.client.HTTPSConnection(url)

        if verify_ssl.lower() == 'false':
            # Ignore certificate verification for self-signed certificate; NOT to be used in production
            self.conn._context = ssl._create_unverified_context()

    def create_report(self, report_name, report_query):
        body = {
            "name": report_name,
            "format": "sql-query",
            "query": report_query,
            "version": "2.3.0"
        }
        self.conn.request("POST", f"{self.base_resource}/reports", json.dumps(body), self.headers)

        resp = self.conn.getresponse()
        data = resp.read()

        # Return JSON response for report template
        return json.loads(data.decode())

    def run_report(self, report_id):
        self.conn.request("POST", f"{self.base_resource}/reports/{report_id}/generate", None, self.headers)

        resp = self.conn.getresponse()
        instance = json.loads(resp.read().decode())

        while True:
            instance_details = self.get_report_details(report_id, instance["id"])

            if any(instance_details["status"] in s for s in ['aborted', 'failed', 'complete']):
                # Return report instance id and status on completion status
                return instance_details
            else:
                # Wait between checking status; reports can take a while to complete
                sleep(5)

    def download_report(self, report_id, instance_id):
        self.conn.request("GET", f"{self.base_resource}/reports/{report_id}/history/{instance_id}/output",
                          None, self.headers)

        resp = self.conn.getresponse()
        data = resp.read().decode()

        # Return JSON response for report instance
        return data

    def delete_report(self, report_id):
        self.conn.request("DELETE", f"{self.base_resource}/reports/{report_id}", None, self.headers)

        resp = self.conn.getresponse()
        data = resp.read()

        # Return JSON response for report instance
        return json.loads(data.decode())

    def get_report_details(self, report_id, instance_id):
        self.conn.request("GET", f"{self.base_resource}/reports/{report_id}/history/{instance_id}", None, self.headers)

        resp = self.conn.getresponse()
        data = resp.read()

        # Return JSON response for report instance
        return json.loads(data.decode())


if __name__ == '__main__':
    HOST = os.environ.get("INSIGHTVM_HOST", "")  # Format: <ip/hostname>:<port>
    USER = os.environ.get("INSIGHTVM_USER", "")  # InsightVM Console user with permissions to generate reports
    PASS = os.environ.get("INSIGHTVM_PASS", "")
    SSL_VERIFY = os.environ.get("INSIGHTVM_SSL_VERIFY",
                                "true")  # Override to False to ignore certification verification

    if any(v is None or v == "" for v in [HOST, USER, PASS]):
        sys.exit("Host, user, or password not defined; check environment variables and try again!")

    # Reference: https://nexpose.help.rapid7.com/docs/understanding-the-reporting-data-model-overview-and-query-design
    QUERIES = {
        "vulnerabilities": """
            SELECT dvr.reference, da.ip_address, da.host_name, da.mac_address, dv.title, dim.operating_system, round(dv.riskscore::numeric, 0) AS risk
            FROM fact_asset_vulnerability_finding favf 
               JOIN dim_operating_system dos dos USING (operating_system_id) 
               JOIN dim_vulnerability dv USING (vulnerability_id) 
               JOIN dim_vulnerability_reference dvr using (vulnerability_id) 
            WHERE dim.operating_system like '%Linux%'
            ORDER BY dim.operating_system
        """
    }

    # Initialize API helper
    api = InsightVmApi(HOST, USER, PASS, SSL_VERIFY)

    # Process each query
    for name, query in QUERIES.items():
        print(f"Generating report for {name} query")
        start_time = datetime.now()

        # Create report template with name and query
        report = api.create_report(f"adhoc-{name}-{uuid.uuid4()}", query)

        # Generate report and poll until completion
        report_instance = api.run_report(report["id"])

        if report_instance["status"] == "complete":
            # Download report; do something with it!
            api.download_report(report["id"], report_instance["id"])

        # Cleanup adhoc report template
        #api.delete_report(report["id"])

        end_time = datetime.now()
        delta = end_time - start_time

        print(f"{name} report generated in {delta.seconds} seconds")
