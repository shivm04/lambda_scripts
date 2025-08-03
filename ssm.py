import boto3
import json
import gzip
import base64
import re
from datetime import datetime, timezone, timedelta

REGION = "ap-south-1"
LOG_GROUP_NAME = "SSM"
EMAIL_FROM = "04shivm@gmail.com"
EMAIL_TO = "04shivm@gmail.com"

ses_client = boto3.client('ses', region_name=REGION)
ec2_client = boto3.client('ec2', region_name=REGION)

def lambda_handler(event, context):
    try:
        data = event["awslogs"]["data"]
        compressed_payload = base64.b64decode(data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        logs_data = json.loads(uncompressed_payload)
    except Exception as e:
        return {"statusCode": 400, "body": f"Log decode failed: {str(e)}"}

    for log_event in logs_data["logEvents"]:
        try:
            message_json = json.loads(log_event.get("message", "{}"))
        except json.JSONDecodeError:
            message_json = {}

        session_data = message_json.get('sessionData', [])
        raw_command_line = session_data[-1] if session_data else ""
        cleaned_command = extract_clean_command(raw_command_line)

        username = extract_username(raw_command_line, message_json.get('runAsUser', 'unknown'))

        utc_time = datetime.fromtimestamp(log_event['timestamp'] / 1000, tz=timezone.utc)
        ist_time = utc_time.astimezone(timezone(timedelta(hours=5, minutes=30)))
        timestamp_utc = utc_time.strftime('%Y-%m-%d %H:%M:%S UTC')
        timestamp_ist = ist_time.strftime('%Y-%m-%d %H:%M:%S IST')
        timestamp = f"{timestamp_utc} / {timestamp_ist}"

        instance_id = message_json.get('target', {}).get('id', 'unknown')
        instance_name = get_instance_name(instance_id)
        raw_json_command = json.dumps(message_json, indent=2)

        log_stream = logs_data.get("logStream", "Unknown")
        log_link = f"https://console.aws.amazon.com/cloudwatch/home?region={REGION}#logsV2:log-groups/log-group/{LOG_GROUP_NAME}/log-events/{log_stream}"

        subject = f"[ALERT] Critical Command on {instance_id} ({instance_name}) by {username}"
        html = build_html_email(timestamp, instance_id, instance_name, username, cleaned_command, raw_json_command, log_stream, log_link)
        send_html_email(subject, html)

    return {"statusCode": 200, "body": "Email(s) sent successfully"}

def extract_clean_command(raw_line):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', raw_line)

    if '#' in cleaned:
        parts = cleaned.split('#', 1)
        cleaned = parts[1].strip()
    else:
        cleaned = cleaned.strip()

    return cleaned

def extract_username(raw_line, fallback_username):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', raw_line)

    match = re.search(r'([a-zA-Z0-9_-]+)@([a-zA-Z0-9\.-]+)', cleaned)
    if match:
        return match.group(1)

    return fallback_username

def get_instance_name(instance_id):
    try:
        reservations = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations']
        tags = reservations[0]['Instances'][0].get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    except Exception:
        pass
    return "Unknown"

def build_html_email(timestamp, instance_id, instance_name, username, command, raw_json, log_stream, log_link):
    return f"""
    <html>
    <head>
      <style>
        body {{ font-family: Arial, sans-serif; background-color: #ffffff; color: #000000; }}
        table {{
          border-collapse: collapse;
          width: 100%;
        }}
        th, td {{
          text-align: left;
          padding: 8px;
          border: 1px solid #ddd;
        }}
        th {{
          background-color: #f44336;
          color: white;
        }}
        .button-container {{
          margin-top: 20px;
        }}
        .button {{
          background-color: #1e88e5;
          color: #ffffff;
          padding: 12px 20px;
          text-decoration: none;
          display: inline-block;
          border-radius: 5px;
          font-size: 16px;
          border: none;
        }}
        .button:hover {{
          background-color: #1565c0;
        }}
        .json-box {{
          margin-top: 20px;
          background: #f4f4f4;
          padding: 15px;
          border-radius: 5px;
          font-family: monospace;
          white-space: pre-wrap;
          color: #333333;
        }}
      </style>
    </head>
    <body>
      <h2>🚨 Critical Command Alert</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Time</td><td>{timestamp}</td></tr>
        <tr><td>Instance ID</td><td>{instance_id}</td></tr>
        <tr><td>Instance Name</td><td>{instance_name}</td></tr>
        <tr><td>Username</td><td>{username}</td></tr>
        <tr><td>Command</td><td><code>{command}</code></td></tr>
        <tr><td>Log Group</td><td>{LOG_GROUP_NAME}</td></tr>
        <tr><td>Log Stream</td><td>{log_stream}</td></tr>
      </table>

      <div class="button-container">
        <a class="button" href="{log_link}" target="_blank">🔍 View Logs in CloudWatch</a>
      </div>

      <div class="json-box">
        <strong>Raw JSON Command:</strong><br>
        {raw_json}
      </div>
    </body>
    </html>
    """

def send_html_email(subject, html_body):
    ses_client.send_email(
        Source=EMAIL_FROM,
        Destination={'ToAddresses': [EMAIL_TO]},
        Message={
            'Subject': {'Data': subject},
            'Body': {'Html': {'Data': html_body}}
        }
    )
