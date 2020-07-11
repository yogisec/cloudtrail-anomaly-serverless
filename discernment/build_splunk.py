import boto3
import time
import requests
import json
import sys


class Splunk:
    # This is used to send the payload to splunk, it sends to sns which triggers another lambda function...the To_Splunk_HEC function will send the payload directly. 
    def To_Splunk_SNS(self, splunk_payload):
        # Create client
        client = boto3.client('sns')

        # Send Payload to SNS
        response = client.publish(
            TopicArn='arn:aws:sns:us-east-1:<ACCOUNT_NUMBER>:SendSplunkPayload',
            Message=json.dumps({'default': splunk_payload}),
            Subject='SendSplunkPayload',
            MessageStructure='json'
        )

        # Read response and parse last_successful_runtime
        # if response['MessageId'] != None:
        if response['MessageId']:
            print('-- Successfully sent message {}'.format(response['MessageId']))
        else:
            # cloud watch error
            # Unable to post to SNS
            raise ValueError('Unable to send SNS message: {} returned from the server'.format(response['HttpStatusCode']))
            sys.exit()

    def To_Splunk_HEC(self, splunk_payload):
        # This function was ported in, and has not been tested, it should work but may need tweaking. The original version of this pushing logs via a SNS message trigger.
        print('-- Sending this to splunk:')
        
        # Splunk HTTPS HEC url below:
        splunk = ''
        splunk_token = ''

        url = f'https://{splunk}/services/collector'
        header = {'Authorization': 'Splunk {}'.format(splunk_token)}
        response = requests.post(url, headers=header, data=splunk_payload)
        if response.status_code != 200 or not requests:
            raise ValueError(f'-- Unable to connect to Splunk: {response.status_code} - {response.reason} status code recieved')
        else:
            print('-- Splunk Connection Successful')

    def Build_Payload(self, event_data, sourcetype):
        dumped_event_data = json.dumps(event_data)
        print('-- Dumped Event Data: ' + dumped_event_data + '\n\n')
        print('-- Building Payload')

        index = '<SPLUNK_INDEX>'
        payload = {'index': index, 'sourcetype': sourcetype, 'event': dumped_event_data, 'time': time.time()}
        formated_payload = json.dumps(payload)

        return formated_payload
