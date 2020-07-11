import boto3
import time
import re
import sys
from build_splunk import Splunk


class Athena:
    def Create_Table(self, account, ct_bucket, business):

        query_string = """CREATE EXTERNAL TABLE IF NOT EXISTS {business}_ct_anomaly_{account} (
        eventVersion STRING,
        userIdentity STRUCT<
            type: STRING,
            principalId: STRING,
            arn: STRING,
            accountId: STRING,
            invokedBy: STRING,
            accessKeyId: STRING,
            userName: STRING,
            sessionContext: STRUCT<
                attributes: STRUCT<
                    mfaAuthenticated: STRING,
                    creationDate: STRING>,
                sessionIssuer: STRUCT<
                    type: STRING,
                    principalId: STRING,
                    arn: STRING,
                    accountId: STRING,
                    userName: STRING>>>,
        eventTime STRING,
        eventSource STRING,
        eventName STRING,
        awsRegion STRING,
        sourceIpAddress STRING,
        userAgent STRING,
        errorCode STRING,
        errorMessage STRING,
        requestParameters STRING,
        responseElements STRING,
        additionalEventData STRING,
        requestId STRING,
        eventId STRING,
        resources ARRAY<STRUCT<
            arn: STRING,
            accountId: STRING,
            type: STRING>>,
        eventType STRING,
        apiVersion STRING,
        readOnly STRING,
        recipientAccountId STRING,
        serviceEventDetails STRING,
        sharedEventID STRING,
        vpcEndpointId STRING
    )
    PARTITIONED BY(region string, year string, month string, day string)
    ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://{bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/'
    TBLPROPERTIES ('classification'='cloudtrail');"""

        athena_query = query_string.format(account=account, bucket=ct_bucket, business=business)

        return athena_query

    # Update Table Partitions for each region:
    def Update_Partitions(self, account, year, month, day, ct_bucket, business):
        query_string = """ALTER TABLE {business}_ct_anomaly_{account}
        ADD IF NOT EXISTS PARTITION (region='ap-northeast-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-northeast-1/{year}/{month}/{day}'
    PARTITION (region='ap-northeast-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-northeast-2/{year}/{month}/{day}'
    PARTITION (region='ap-northeast-3',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-northeast-3/{year}/{month}/{day}'
    PARTITION (region='ap-south-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-south-1/{year}/{month}/{day}'
    PARTITION (region='ap-south-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-south-2/{year}/{month}/{day}'
    PARTITION (region='ap-southeast-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-southeast-1/{year}/{month}/{day}'
    PARTITION (region='ap-southeast-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ap-southeast-2/{year}/{month}/{day}'
    PARTITION (region='ca-central-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ca-central-1/{year}/{month}/{day}'
    PARTITION (region='ca-central-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/ca-central-2/{year}/{month}/{day}'
    PARTITION (region='eu-central-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-central-1/{year}/{month}/{day}'
    PARTITION (region='eu-central-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-central-2/{year}/{month}/{day}'
    PARTITION (region='eu-north-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-north-1/{year}/{month}/{day}'
    PARTITION (region='eu-west-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-west-1/{year}/{month}/{day}'
    PARTITION (region='eu-west-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-west-2/{year}/{month}/{day}'
    PARTITION (region='eu-west-3',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/eu-west-3/{year}/{month}/{day}'
    PARTITION (region='sa-east-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/sa-east-1/{year}/{month}/{day}'
    PARTITION (region='us-east-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/us-east-1/{year}/{month}/{day}'
    PARTITION (region='us-east-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/us-east-2/{year}/{month}/{day}'
    PARTITION (region='us-west-1',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/us-west-1/{year}/{month}/{day}'
    PARTITION (region='us-west-2',year='{year}',month='{month}',day='{day}') LOCATION 's3://{ct_bucket}/CloudTrail/AWSLogs/{account}/CloudTrail/us-west-2/{year}/{month}/{day}';"""
        athena_query = query_string.format(account=account, year=year, month=month, day=day, ct_bucket=ct_bucket, business=business)

        return athena_query

    def Query(self, athena_query, athena_database, athena_s3_bucket, query_type):
        athena_output_location = f's3://{athena_s3_bucket}/cloudtrail_anomaly/athena_results/{query_type}/'
        athena_client = boto3.client('athena')
        splunk = Splunk()

        too_many_exceptions = True
        # This loop is a backoff loop if we hit a rate limit for query executions for athena
        while too_many_exceptions is True:
            try:
                response = athena_client.start_query_execution(
                    QueryString=athena_query,
                    QueryExecutionContext={'Database': athena_database},
                    ResultConfiguration={'OutputLocation': athena_output_location})
                too_many_exceptions = False
            except Exception as e:
                error_string = str(e)
                print('Printing Error: ' + error_string)
                if 'TooManyRequestsException' in error_string:
                    too_many_exceptions = True
                    # Backoff timer, if needed make it random
                    time.sleep(2)

                note = 'The athena query failed!'
                event_data = {'error_note': 'Error with Athena Query in muster.', 'query_response': str(e), 'note': note}
                sourcetype = 'lambda:cloudtrailanomaly:error'
                splunk_payload = splunk.Build_Payload(event_data, sourcetype)
                splunk.To_Splunk_SNS(splunk_payload)
                # sys.exit('Athena Query State is failed')

        execution_id = response['QueryExecutionId']
        print('---- Waiting for execution Id: ' + execution_id)

        state = 'RUNNING'

        # wait 3 mins to run query before moving on
        max_execution_timeout = 36

        splunk = Splunk()

        while (max_execution_timeout > 0 and state in ['RUNNING']):
            max_execution_timeout = max_execution_timeout - 1
            execution_response = athena_client.get_query_execution(
                QueryExecutionId=execution_id
            )

            print('---- Execution Response: ' + str(execution_response))

            if execution_response['QueryExecution']['Status']['State'] == 'QUEUED':
                print(f'---- Query queued for execution id {execution_id} waiting for it to change to start.')
                state = 'RUNNING'
            elif 'QueryExecution' in execution_response and \
                    'Status' in execution_response['QueryExecution'] and \
                    'State' in execution_response['QueryExecution']['Status']:
                state = execution_response['QueryExecution']['Status']['State']
                print(f'---- Query currently {state} for execution id {execution_id} waiting for it to finish.')
                if state == 'FAILED':
                    note = 'The athena query failed!'
                    event_data = {'error_note': 'Error with Athena Query in muster.', 'query_response': str(execution_response), 'note': note}
                    sourcetype = 'lambda:cloudtrailanomaly:error'
                    splunk_payload = splunk.Build_Payload(event_data, sourcetype)
                    splunk.To_Splunk_SNS(splunk_payload)
                    raise ValueError('Athena Query Failed ')
                    sys.exit('Athena Query State is failed')
                elif state == 'SUCCEEDED':
                    s3_path = execution_response['QueryExecution']['ResultConfiguration']['OutputLocation']
                    filename = re.findall(r'.*\/(.*)', s3_path)[0]
                    return filename
            time.sleep(5)
        return False

    def Get_Results(self, athena_s3_bucket, s3_key):
        print(f'---- Downloading and reading S3 file s3://{athena_s3_bucket}/{s3_key}')
        s3_client = boto3.client('s3')
        s3_object = s3_client.get_object(Bucket=athena_s3_bucket, Key=s3_key)
        data = s3_object['Body'].read()
        return data.decode('utf-8').replace('"', '').split('\n')
