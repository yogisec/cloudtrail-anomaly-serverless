import json
import os
import datetime
import time
import boto3
from random import randint
from organization import Get_Org_Accounts

athena_s3_bucket = os.environ['athena_results_bucket']
athena_database = os.environ['athena_database']
dynamodb = os.environ['dynamodb']
parent_account = os.environ['parent_account']


def lambda_handler(event, context):

    accounts = {}
    accounts_blob = Get_Org_Accounts(parent_account)
    
    # If splitting the muster script up by business unit or some other key value in the account name, this facilitates the capability to do so. 
    '''
    for account_number, account_meta in accounts_blob.items():
        if '<BUSINESS>' in account_meta['name'].lower():
            accounts[account_number] = {
                'ct_bucket': '<CLOUDTRAIL_BUCKET>',
                'name': account_meta['name'],
                'email': account_meta['email'],
                'business': '<BUSINESS>'
            }
    '''

    # If the loop above is not used, use the loop below. This will loop through all of the accounts returned from the organization and kick of the discernment for each of them. Please note that this may cause S3 API rate limit errors when athena starts to run its queries. This will depened on how many accounts you are attempting to analyze.

    for account_number, account_meta in accounts_blob.items():
        accounts[account_number] = {
            'ct_bucket': '<CLOUDTRAIL_BUCKET>',
            'name': account_meta['name'],
            'email': account_meta['email'],
            'business': '<BUSINESS>'
        }

    # Building a date object to be used to find current date S3 object path and to build S3 object path for faster Athena Searches
    year = datetime.datetime.utcnow().strftime('%Y')
    month = datetime.datetime.utcnow().strftime('%m')
    day = datetime.datetime.utcnow().strftime('%d')
    current_date = []
    current_date.extend([year, month, day])

    # Send account and current_date to SNS to spin up additional lambdas
    print('-- Kicking everything off. Sending data to SNS to spawn childern.')

    # If there are any accounts which need to be skipped entirely for any reason, add them here.
    skipped_accounts = ['']

    for account, account_meta in accounts.items():
        if account in skipped_accounts:
            print('skipping unmanged account')
        else:
            sleeper = randint(0, 5)
            arn = 'arn:aws:sns:us-east-1:<ACCOUNT_NUMBER>:cloudtrailanomaly_main'

            message = {
                "account": account,
                "current_date": current_date,
                "athena_database": athena_database,
                "athena_s3_bucket": athena_s3_bucket,
                "ct_bucket": account_meta['ct_bucket'],
                "dynamodb": dynamodb,
                "business": account_meta['business'],
                "owner": account_meta['email'],
                "name": account_meta['name']
            }

            client = boto3.client('sns')
            client.publish(
                TargetArn=arn,
                Message=json.dumps({'default': json.dumps(message)}),
                MessageStructure='json'
            )

            print('-- SNS message spawned for account: {}'.format(account))
            time.sleep(sleeper)

    print('-- All Done, TTFN')
