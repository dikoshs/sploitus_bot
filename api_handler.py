import requests
from dotenv import load_dotenv
import os

load_dotenv(override=True)


class ApiHandler:
    def __init__(self):
        self.API_URL = os.getenv('API_URL')
        self.API_KEY = os.getenv('API_KEY')
        # api/v1/my_vulnerabilities
        # api/v1/scan

    def get_my_vulnerabilities(self):
        response = requests.get(self.API_URL + "my_vulnerabilities/", headers={
            "Authorization": f"APIKEY {self.API_KEY}",
        })

        my_vulns = response.json()

        return my_vulns

    def scan_vulns(self, domain_or_ip):
        # try:
            response = requests.post(self.API_URL + "scan/", headers={
                "Authorization": f"APIKEY {self.API_KEY}",
            }, data={
                "query": domain_or_ip,
            })

            if response.status_code == 202:
                return True
            elif response.status_code == 401:
                return "Unauthorized"
            else:
                return False
        # except Exception as e:
        #     return False

    def get_all_vulns(self):
        response = requests.get(self.API_URL + "vulnerabilities/", headers={
            "Authorization": f"APIKEY {self.API_KEY}",
        })

        my_vulns = response.json()

        return my_vulns

    def get_all_vuln_by_id(self, id):
        response = requests.get(self.API_URL + f"get_vulnerabilities/{id}", headers={
            "Authorization": f"APIKEY {self.API_KEY}",
        })

        my_vulns = response.json()
        print("FFFFFFF:", my_vulns)

        return my_vulns
