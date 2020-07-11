import boto3
import pytz
import datetime
from check_dynamo import Query_Dynamo


class Assume_Role:
    def __init__(self):
        self.splunk_token2 = ''
        self.splunk_url2 = ''

    def __Get_Roles(self, target_account):
        print(f'-- Getting roles from account: {target_account}')

        # No need to pull creds for an account we are already in.
        if target_account == '':
            iam_client = boto3.client('iam')
        else:
            role = f"arn:aws:iam::{target_account}:role/security-lambda"
            session = "CloudTrailAnomaly"
            sts_connection = boto3.client('sts')

            sts_response = sts_connection.assume_role(
                RoleArn=role,
                RoleSessionName=session
            )

            temp_access_key = sts_response["Credentials"]["AccessKeyId"]
            temp_secret_access_key = sts_response["Credentials"]["SecretAccessKey"]
            temp_session_token = sts_response["Credentials"]["SessionToken"]

            iam_client = boto3.client(
                'iam',
                aws_access_key_id=temp_access_key,
                aws_secret_access_key=temp_secret_access_key,
                aws_session_token=temp_session_token)

        response = iam_client.list_roles(PathPrefix='/', MaxItems=100)
        roles = {}
        while True:
            next_token = response.get('Marker', None)
            for role in response.get('Roles', []):
                roles[role['Arn']] = role
            if next_token:
                response = iam_client.list_roles(Marker=next_token)
            else:
                break
        return roles

    def __Event_Meta_Details(self, applicable_to, role_meta):
        event_enrichment = {}

        if 'Service' in applicable_to:
            associated_with = applicable_to['Service']
            association_type = 'Service'
            association_message = 'AWS services can be associated with this role. The following service(s) can be associated with this particular role: {}'.format(str(associated_with))
            severity = 'High'
        elif 'Federated' in applicable_to:
            associated_with = applicable_to['Federated']
            association_type = 'Federated'
            association_message = 'Federated users can use this role. This means that users must first authenticate outside of aws.'
            # If users are auth'd though our IDP mark it as informational, other controls will have to do the heavy lifting here, if its not through our IDP, its a vendor 3rd party account, mark it as high.
            if 'OKTA, OneLogin, PingFed, ETC.' in associated_with:
                severity = 'Informational'
            else:
                severity = 'High'
        elif 'AWS' in applicable_to:
            associated_with = applicable_to['AWS']
            association_type = 'AWS'
            association_message = 'This is a role from another account. Someone or thing requested temporary access keys to this account and made API calls.'
            severity = 'Medium'
        else:
            # This is a catch all for the unknown.
            associated_with = '?'
            association_type = '?'
            association_message = str(role_meta)
            severity = 'Informational'

        event_enrichment['associate_with'] = associated_with
        event_enrichment['assoication_type'] = association_type
        event_enrichment['association_message'] = association_message
        event_enrichment['severity'] = severity

        return event_enrichment

    def Process(self, account, dynamo_table, cloud_trail_events, business, owner, account_name):
        roles = self.__Get_Roles(account)
        print('-- Found {} roles. Checking activity for each role.'.format(len(roles)))

        event_data_blob = []

        for role_arn, role_meta in roles.items():
            role_name = role_meta['RoleName']
            principal_id = role_meta['RoleId']
            create_date = role_meta['CreateDate']
            applicable_to = role_meta['AssumeRolePolicyDocument']['Statement'][0]['Principal']

            # Determining what this role can be associated with, person, service, etc.

            event_enrichment = self.__Event_Meta_Details(applicable_to, role_meta)

            associated_with = event_enrichment['associate_with']
            association_type = event_enrichment['assoication_type']
            association_message = event_enrichment['association_message']
            severity = event_enrichment['severity']

            # Items in this list will be added to Dynamo, but will not trigger alerts to splunk
            roles_to_ignore = ['']

            # Items in this list will be added to Dynamo, but will not be added to role_actions list returned from 'Query_Dynamo' and will not trigger an alert.
            actions_to_ignore = ['']

            # Use this sparingly this whitelists a large amount of aws calls
            # this is disabled right now causes some unforseen issues
            services_to_ignore = ['']

            role_actions = []

            print(f'-- Checking recent actions for role - {principal_id}')
            for call in cloud_trail_events:
                call_principal = call.split(',')[2]
                if call_principal == principal_id:
                    returned_role_actions = Query_Dynamo(call, dynamo_table, actions_to_ignore, role_name, account, services_to_ignore)
                    role_actions.extend(returned_role_actions)

            if len(role_actions) > 0:
                arn = role_arn
                skip_alert = False

                # If the role is too new, don't alert. Will cause tons of noise, not worth it.
                # use other methods to find bad
                if create_date > datetime.datetime.now(pytz.utc) - datetime.timedelta(days=15):
                    skip_alert = True
                    print(f'---- {role_name} in {account} is too new, skipping alert')
                if 'aws-service-role' in arn.split('/'):
                    skip_alert = True
                    print(f'---- {role_name} in {account} is an AWS service role, skipping alert')
                if role_name in roles_to_ignore:
                    skip_alert = True
                    print(f'---- {role_name} in {account} is an role we want to ignore, skipping alert')
                if len(role_actions) < 5:
                    severity = 'Informational'
                    print(f'---- {role_name} in {account} had less than 5 new detected actions, dropping alert severuity to Informational.')
                if not skip_alert:
                    print(f'---- Sending alert for {role_name} in account {account} with the principalId of {principal_id}.')
                    print('---- Because of the following new actions: ' + str(role_actions))

                    note = 'Activity has been detected that is not within the past 90 days baseline activity for this role and account.'

                    event_data = {
                        'role_name': role_name,
                        'account': account,
                        'role_arn': role_arn,
                        'principalId': principal_id,
                        'role_actions': role_actions,
                        'alert_name': 'CloudTrailAnomaly',
                        'alert_note': note,
                        'association_type': association_type,
                        'associated_with': associated_with,
                        'association_message': association_message,
                        'severity': severity,
                        'business': business,
                        'account_owner': owner,
                        'account_name': account_name
                    }

                    event_data_blob.append(event_data)

            else:
                print(' ---- No new actions to report.')

        return event_data_blob

# Class for anomaly detection for logon type Root. If you have GuardDuty and already alert on root logins and usage (Policy:IAMUser/RootCredentialUsage) this may not be necessary 
class Root:

    def Actions(self):
        print('root actions!!!')
        return 'Root Actions!!!'

# Class for anomaly detection for logon type IAMUser
class IAMUser:

    def Actions(self):
        print('IAMUSER actions!!!')
        return 'IAMUSER Actions!!!'
