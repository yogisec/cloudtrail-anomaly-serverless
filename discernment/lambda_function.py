import boto3
import json
import time
import identity_types
from ath import Athena
from build_splunk import Splunk


def lambda_handler(event, context):

    raw_message = json.loads(event['Records'][0]['Sns']['Message'])
    account = raw_message['account']
    current_date = raw_message['current_date']
    athena_s3_bucket = raw_message['athena_s3_bucket']
    athena_database = raw_message['athena_database']
    ct_bucket = raw_message['ct_bucket']
    dynamo_database = raw_message['dynamodb']
    business = raw_message['business']
    owner = raw_message['owner'],
    account_name = raw_message['name']

    year = current_date[0]
    month = current_date[1]
    day = current_date[2]

    athena = Athena()

    print('-- Getting Athena Ready')
    build_table_query = athena.Create_Table(account, ct_bucket, business)

    query_type = 'table_con'
    filename = athena.Query(build_table_query, athena_database, athena_s3_bucket, query_type)
    time.sleep(1)
    print('---- Done making Athena table for account: {} if it did not already exist. Here is the response file: {}'.format(account, str(filename)))

    print('---- Checking the table search paritions, if not partitioned making query to define them.')
    print('---- Building table partitions if they do not already exist')
    build_partition_query = athena.Update_Partitions(account, year, month, day, ct_bucket, business)

    time.sleep(1)
    athena.Query(build_partition_query, athena_database, athena_s3_bucket, query_type)

    print('---- Done building partitions if they were needed.')
    time.sleep(2)

    print('-- Getting account activity for the past hour.')

    # This query pulls back cloudtrail actvity for the bast hour
    # This will let us pull in all the useridentity types, and process them specifically looking for assumedrole, root, etc. and process them accordingly.

    account_activity_query = """SELECT DISTINCT eventsource, eventname, useridentity.sessioncontext.sessionissuer.principalid, useridentity.type FROM "{business}_ct_anomaly_{account}"
WHERE year='{year}'
AND month='{month}'
AND day='{day}'
AND eventTime > to_iso8601(current_timestamp - interval '1' hour);""".format(account=account, year=year, month=month, day=day, business=business)

    query_type = 'activity'
    account_activity_file = False
    while account_activity_file is False:
        account_activity_file = athena.Query(account_activity_query, athena_database, athena_s3_bucket, query_type)

    activity_s3_key = 'cloudtrail_anomaly/athena_results/activity/' + account_activity_file

    # If we need to we can send the activity key through sns to another downstream lambda, this may help with run durtion timeouts if
    # we encounter them once we begin to scale this.
    cloud_trail_events = athena.Get_Results(athena_s3_bucket, activity_s3_key)
    # print(str(cloud_trail_events))

    # Splunk details to be used a bit later
    sourcetype = 'lambda:cloudtrailanomaly'
    splunk = Splunk()

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    dynamo_table = dynamodb.Table(dynamo_database)

    assume_role_events = []
    root_events = []
    iam_user_events = []

    # Loop through the events for the past hour. Parse out each 'identity type' and add the event to a list based on the type
    # This allows us to handle and process the event
    # learn more about identity types here:
    # https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html

    for call in cloud_trail_events[1:-1]:
        identity_type = call.split(',')[3]
        if identity_type == 'AssumedRole':
            assume_role_events.append(call)
        elif identity_type == 'Root':
            root_events.append(call)
        elif identity_type == 'IAMUser':
            iam_user_events.append(call)

    # please find a better name for this
    event_data_blob_blob = []

    # Analyze the 'AssumedRole' identity type
    Assume_Role = identity_types.Assume_Role()

    if assume_role_events:
        event_data_blob = Assume_Role.Process(account, dynamo_table, assume_role_events, business, owner, account_name)
        if event_data_blob:
            for event in event_data_blob:
                event_data_blob_blob.append(event)

    # Analyze the 'Root' identity type
    Root = identity_types.Root()

    if root_events:
        event_data_blob = Root.Actions()
        print(event_data_blob)
        '''
        if event_data_blob:
            for event in event_data_blob:
                event_data_blob_blob.append(event)
        '''

    # Analyze the 'IAMUser' identity type
    IAMUser = identity_types.IAMUser()

    if iam_user_events:
        event_data_blob = IAMUser.Actions()
        print(event_data_blob)
        '''
        if event_data_blob:
            for event in event_data_blob:
                event_data_blob_blob.append(event)
        '''

    # Now that everything is analyzed, lets send it to splunk. Right now, sending 1 event at a time
    # Perhaps in the future we'll batch this and only hit the Splunk HEC once.
    # We don't expect too many of these api calls, so 1 call per event isn't horrible

    for event in event_data_blob_blob:
        splunk_payload = splunk.Build_Payload(event, sourcetype)
        splunk.To_Splunk_HEC(splunk_payload)

    print("-- Muster Lambda finished. ")
