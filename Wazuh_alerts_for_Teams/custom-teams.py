#!/usr/bin/env python3

import sys
import json
import requests
import logging

# Configuration
LOG_FILE = "/var/ossec/logs/custom-teams.log"

# Logging configuration
logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)

def send_to_teams(webhook_url, alert):
    """
    Send the alert to Microsoft Teams via the webhook.
    """
    try:
        # Extract relevant fields from the alert
        timestamp = alert.get("timestamp", "N/A")
        rule_level = alert.get("rule", {}).get("level", "N/A")
        rule_description = alert.get("rule", {}).get("description", "N/A")
        agent_name = alert.get("agent", {}).get("name", "N/A")
        agent_id = alert.get("agent", {}).get("id", "N/A")

        # Create the message card for Teams
        teams_message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0078D7" if int(rule_level) < 10 else "FF0000",  # Green for low severity, Red for high severity
            "summary": "Wazuh Alert",
            "sections": [
                {
                    "activityTitle": "Wazuh Alert Notification",
                    "facts": [
                        {"name": "Timestamp", "value": timestamp},
                        {"name": "Agent", "value": f"{agent_name} (ID: {agent_id})"},
                        {"name": "Rule Level", "value": rule_level},
                        {"name": "Description", "value": rule_description}
                    ],
                    "markdown": True
                }
            ]
        }

        # Send the message to Teams
        response = requests.post(
            webhook_url,
            json=teams_message,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            logging.info("Alert sent to Microsoft Teams successfully.")
        else:
            logging.error(f"Failed to send alert to Microsoft Teams. Status code: {response.status_code}, Response: {response.text}")

    except Exception as e:
        logging.error(f"Error sending alert to Microsoft Teams: {str(e)}")

def main():
    """
    Main function to read the alert and send it to Teams.
    """
    try:
        # Log the received arguments for debugging
        logging.info(f"Received arguments: {sys.argv}")

        # Ensure at least alert file and webhook URL exist
        if len(sys.argv) < 3:
            logging.error("Wrong arguments. Expected: <alert_file> <webhook_url>")
            sys.exit(1)

        # Extract the alert file
        alert_file = sys.argv[1]

        # Extract the first non-empty webhook URL
        webhook_url = next((arg for arg in sys.argv[2:] if arg.strip()), None)

        if not webhook_url:
            logging.error("Webhook URL is missing or empty.")
            sys.exit(1)

        # Read the alert file
        with open(alert_file, "r") as f:
            alert = json.load(f)

        # Send the alert to Teams
        send_to_teams(webhook_url, alert)

    except Exception as e:
        logging.error(f"Error processing alert: {str(e)}")

if __name__ == "__main__":
    main()
