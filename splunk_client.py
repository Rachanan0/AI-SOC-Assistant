import os
import json
import time

import splunklib.client as client
from dotenv import load_dotenv

load_dotenv()


class SplunkClient:

    def __init__(self):
        self.host = os.getenv("SPLUNK_HOST")
        self.port = int(os.getenv("SPLUNK_PORT"))
        self.username = os.getenv("SPLUNK_USERNAME")
        self.password = os.getenv("SPLUNK_PASSWORD")

    def connect(self):
        return client.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password
        )

    def search(self, query, count=10):

        service = self.connect()

        job = service.jobs.create(query)

        while not job.is_done():
            time.sleep(0.5)

        response = job.results(
            output_mode="json",
            count=count
        )

        data = response.read().decode("utf-8")

        results = json.loads(data)

        return results.get("results", [])