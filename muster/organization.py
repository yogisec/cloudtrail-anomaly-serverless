import boto3


def Get_Org_Accounts(parent_account):
    # print('-- Getting roles from account: {}'.format(target_account))

    role = "arn:aws:iam::{}:role/security-lambda".format(parent_account)
    session = "CloudTrailAnomaly"
    sts_connection = boto3.client('sts')

    sts_response = sts_connection.assume_role(
        RoleArn=role,
        RoleSessionName=session
    )

    temp_access_key = sts_response["Credentials"]["AccessKeyId"]
    temp_secret_access_key = sts_response["Credentials"]["SecretAccessKey"]
    temp_session_token = sts_response["Credentials"]["SessionToken"]

    organizations_client = boto3.client(
        'organizations',
        aws_access_key_id=temp_access_key,
        aws_secret_access_key=temp_secret_access_key,
        aws_session_token=temp_session_token)

    response = organizations_client.list_accounts()
    print(str(response))

    accounts = {}
    while True:
        next_token = response.get('NextToken', None)
        for account in response.get('Accounts', []):
            if account['Status'] == 'ACTIVE':
                email = account['Email']
                name = account['Name']
                accountId = account['Id']
                accounts[accountId] = {'email': email, 'name': name}
        if next_token:
            response = organizations_client.list_accounts(NextToken=next_token)
        else:
            break
    return accounts
