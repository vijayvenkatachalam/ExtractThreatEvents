import requests
import csv
import configparser
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

endpoint = config.get('graphql', 'endpoint')
token = config.get('graphql', 'token')
duration = config.get('settings', 'duration')
x_value = config.getint('settings', 'x_value')
environment = config.get('settings', 'environment')

# Calculate time range
end_time = datetime.utcnow()
if duration == 'last_minutes':
    start_time = end_time - timedelta(minutes=x_value)
elif duration == 'last_hours':
    start_time = end_time - timedelta(hours=x_value)
elif duration == 'last_days':
    start_time = end_time - timedelta(days=x_value)
else:
    raise ValueError("Invalid duration setting in config file. Use 'last_minutes', 'last_hours', or 'last_days'.")

start_time_iso = start_time.isoformat() + 'Z'
end_time_iso = end_time.isoformat() + 'Z'

# GraphQL query template
data_query_template = """
query ($startTime: DateTime!, $endTime: DateTime!, $limit: Int!, $offset: Int!) {
  events(
    limit: $limit
    offset: $offset
    between: {
      startTime: $startTime
      endTime: $endTime
    }
    filterBy: [
      {
        keyExpression: { key: "threatCategory" }
        operator: NOT_IN
        value: ["Null"]
        type: ATTRIBUTE
      },
      {
        keyExpression: { key: "environment" }
        operator: LIKE
        value: "%s"
        type: ATTRIBUTE
      }
    ]
  ) {
    results {
      id
      name: attribute(expression: { key: "name" })
      timestamp: attribute(expression: { key: "timestamp" })
      type: attribute(expression: { key: "type" })
      environment: attribute(expression: { key: "environment" })
      spanId: attribute(expression: { key: "spanId" })
      apiId: attribute(expression: { key: "apiId" })
      apiName: attribute(expression: { key: "apiName" })
      apiUri: attribute(expression: { key: "apiUri" })
      category: attribute(expression: { key: "category" })
      serviceId: attribute(expression: { key: "serviceId" })
      serviceName: attribute(expression: { key: "serviceName" })
      eventDescription: attribute(expression: { key: "eventDescription" })
      actorEntityId: attribute(expression: { key: "actorEntityId" })
      actorName: attribute(expression: { key: "actorName" })
      actorIpAddress: attribute(expression: { key: "actorIpAddress" })
      actorDevice: attribute(expression: { key: "actorDevice" })
      actorSession: attribute(expression: { key: "actorSession" })
      securityScore: attribute(expression: { key: "securityScore" })
      securityScoreCategory: attribute(expression: { key: "securityScoreCategory" })
      securityEventCategory: attribute(expression: { key: "securityEventCategory" })
      threatCategory: attribute(expression: { key: "threatCategory" })
      securityEventTypeId: attribute(expression: { key: "securityEventTypeId" })
      spanStartTimestamp: attribute(expression: { key: "spanStartTimestamp" })
      actorCountry: attribute(expression: { key: "actorCountry" })
      actorState: attribute(expression: { key: "actorState" })
      actorCity: attribute(expression: { key: "actorCity" })
      eventImpactLevel: attribute(expression: { key: "eventImpactLevel" })
      eventConfidenceLevel: attribute(expression: { key: "eventConfidenceLevel" })
      ipCategories: attribute(expression: { key: "ipCategories" })
      ipReputationLevel: attribute(expression: { key: "ipReputationLevel" })
      ipConnectionType: attribute(expression: { key: "ipConnectionType" })
      ipAsn: attribute(expression: { key: "ipAsn" })
      ipOrganisation: attribute(expression: { key: "ipOrganisation" })
      traceId: attribute(expression: { key: "traceId" })
      anomalousAttribute: attribute(expression: { key: "anomalousAttribute" })
      scannerType: attribute(expression: { key: "scannerType" })
      SERVICE: entity(type: "SERVICE") {
        id: attribute(expression: { key: "id" })
        name: attribute(expression: { key: "name" })
        __typename
      }
      API: entity(type: "API") {
        id: attribute(expression: { key: "id" })
        name: attribute(expression: { key: "name" })
        isAuthenticated: attribute(expression: { key: "isAuthenticated" })
        hasPii: attribute(expression: { key: "hasPii" })
        changeLabel: attribute(expression: { key: "changeLabel" })
        changeLabelTimestamp: attribute(expression: { key: "changeLabelTimestamp" })
        __typename
      }
      __typename
    }
    __typename
  }
}
"""

# Populate the environment value dynamically
data_query = data_query_template % environment


def fetch_data(start_time, end_time, limit, offset):
    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'application/json'
    }
    variables = {
        'startTime': start_time,
        'endTime': end_time,
        'limit': limit,
        'offset': offset
    }
    request_payload = {
        'query': data_query,
        'variables': variables
    }
    logger.info(f"Full GraphQL Request: {request_payload}")

    response = requests.post(
        endpoint,
        json=request_payload,
        headers=headers
    )

    # Log response status and body
    logger.info(f"Response Status Code: {response.status_code}")
    logger.info(f"Response Body: {response.text}")

    response.raise_for_status()
    return response.json()


def process_data(result, seen_ids):
    data = result.get('data', {}).get('events', {}).get('results', [])
    processed_data = []
    for record in data:
        if record['id'] not in seen_ids:
            # Convert epoch timestamp to human-readable format
            timestamp = datetime.utcfromtimestamp(record['timestamp'] / 1000).isoformat() + 'Z'
            row = [
                record['id'], record['name'], timestamp, record['type'], record['environment'],
                record['spanId'], record['apiId'], record['apiName'], record['apiUri'], record['category'],
                record['serviceId'], record['serviceName'], record['eventDescription'], record['actorEntityId'],
                record['actorName'], record['actorIpAddress'], record['actorDevice'], record['actorSession'],
                record['securityScore'], record['securityScoreCategory'], record['securityEventCategory'],
                record['threatCategory'], record['securityEventTypeId'], record['spanStartTimestamp'],
                record['actorCountry'], record['actorState'], record['actorCity'], record['eventImpactLevel'],
                record['eventConfidenceLevel'], record['ipCategories'], record['ipReputationLevel'],
                record['ipConnectionType'], record['ipAsn'], record['ipOrganisation'], record['traceId'],
                record['anomalousAttribute'], record['scannerType'],
                record['SERVICE']['id'] if record['SERVICE'] else None,
                record['SERVICE']['name'] if record['SERVICE'] else None,
                record['API']['id'] if record['API'] else None,
                record['API']['name'] if record['API'] else None,
                record['API']['isAuthenticated'] if record['API'] else None,
                record['API']['hasPii'] if record['API'] else None,
                record['API']['changeLabel'] if record['API'] else None,
                record['API']['changeLabelTimestamp'] if record['API'] else None
            ]
            processed_data.append(row)
            seen_ids.add(record['id'])
    return processed_data


def write_to_csv(all_data, filename='output.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write headers
        headers = [
            'id', 'name', 'timestamp', 'type', 'environment', 'spanId', 'apiId',
            'apiName', 'apiUri', 'category', 'serviceId', 'serviceName', 'eventDescription',
            'actorEntityId', 'actorName', 'actorIpAddress', 'actorDevice', 'actorSession',
            'securityScore', 'securityScoreCategory', 'securityEventCategory', 'threatCategory',
            'securityEventTypeId', 'spanStartTimestamp', 'actorCountry', 'actorState',
            'actorCity', 'eventImpactLevel', 'eventConfidenceLevel', 'ipCategories',
            'ipReputationLevel', 'ipConnectionType', 'ipAsn', 'ipOrganisation', 'traceId',
            'anomalousAttribute', 'scannerType', 'serviceId', 'serviceName', 'apiId',
            'apiName', 'isAuthenticated', 'hasPii', 'changeLabel', 'changeLabelTimestamp'
        ]
        writer.writerow(headers)
        # Write data rows
        for batch in all_data:
            writer.writerows(batch)


def main():
    limit = 1000
    offset = 0
    all_data = []
    futures = []
    seen_ids = set()
    more_data = True

    with ThreadPoolExecutor(max_workers=10) as executor:
        while more_data:
            futures.append(executor.submit(fetch_data, start_time_iso, end_time_iso, limit, offset))
            offset += limit
            if len(futures) >= 10:  # Adjust this value based on the number of records and available resources
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        data = process_data(result, seen_ids)
                        if data:
                            all_data.append(data)
                        if len(data) < limit:  # No more data, exit loop
                            more_data = False
                    except Exception as e:
                        logger.error(f"Error fetching data: {e}")
                futures = []

        for future in as_completed(futures):
            try:
                result = future.result()
                data = process_data(result, seen_ids)
                if data:
                    all_data.append(data)
            except Exception as e:
                logger.error(f"Error fetching data: {e}")

    write_to_csv(all_data)


if __name__ == '__main__':
    main()
