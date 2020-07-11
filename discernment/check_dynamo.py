import time
import datetime


def Query_Dynamo(call, dynamo_table, actions_to_ignore, role_name, account, services_to_ignore):

    # Set the record TTL in dynamodb to 90 days from now
    # This is when each record that is checked will be set to expire
    # essentially, kicking the expiration date 90 days into the future so we don't loose events
    new_ttl = int(time.mktime((datetime.datetime.now() + datetime.timedelta(days=90)).timetuple()))

    role_actions = []

    split_activity = call.split(',')
    principal_id = split_activity[2]
    eventName = split_activity[1]
    eventSource = split_activity[0]
    service_action = eventSource + ':' + eventName

    if len(service_action) == 0:
        quit()

    print(f'---- Checking recently seen action: {service_action} from principal: {principal_id} / role: {role_name} in account {account} against DynamoDB baseline behavior.')

    key = {'RoleId': principal_id, 'Action': service_action}

    response = dynamo_table.get_item(Key=key)

    if response and 'Item' in response:
        dynamo_table.update_item(
            Key=key,
            UpdateExpression='SET #ttl = :ttl',
            ExpressionAttributeNames={'#ttl': 'TTL'},
            ExpressionAttributeValues={':ttl': new_ttl})
    else:
        if service_action not in actions_to_ignore:
            role_actions.append(service_action)
            print(f'---- Newly seen action:{principal_id}  {role_name} - {service_action} in {account}')
        '''
        elif service_action.split(':')[0] in services_to_ignore:
            role_actions.append(service_action)
            print('---- Newly seen action:{}  {} - {} in {}'.format(principal_id, role_name, service_action, account))
        '''

        dynamo_table.put_item(Item={'RoleId': principal_id,
                                    'Action': service_action,
                                    'TTL': new_ttl})
    return role_actions
