import os
import json
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

        service = client.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password
        )

        return service


    def search(self, query):

        service = self.connect()

        job = service.jobs.create(query)


        # Wait until search completes
        while not job.is_done():
            pass


        # Get JSON response
        response = job.results(
            output_mode="json"
        )


        # Convert bytes to string
        data = response.read().decode("utf-8")


        # Convert JSON string to dictionary
        json_data = json.loads(data)


        # Return only events
        return json_data["results"]