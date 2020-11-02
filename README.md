# cloudtrail-anomaly-serverless

## Overview

This repo contains a CloudTrail Anomaly detection serverless application. Its purpose is to examine cloudtrail logs for the past hour and compare them to a 90 day historical baseline by principalId. If there is a deviation it enters into an alert scenario. If the criteria is met to send an alert an event is sent to Splunk.

The muster lambda function is designed to be split by business unit or some other organization structure which runs based on a cloudwatch cron event. This is designed to spread the load of the queries so that we are not overwhelming aws api calls for the account.

Each muster function calls the discernment function. Each account will have its own instance of the discernment script. This scirpt is designed to make the choice, is it an anomaly or not and then alert.

### Data Flow
Below is the basic data flow
![](data_flow.png)

1. The application makes a query to the primary organization account for a list of all accounts managed within the organization. The application sorts the list and pulls out the business unit(s) it is currently planning to check for anomalies.
2. The application submits several queries to Athena.

```
1. Create a table for the account it is about to query for if it does not exist
2. Create a partition within the table for today's date if it does not exist (allows for efficient searches)
3. Search for activity from the past hour from this account select the distinct event data by principalid
```
3. Athena queries the data stored within the S3 bucket for the account for activity within the past hour
4. Athena stores the results to a `results` bucket within S3
5. Once the search is `SUCCESSFUL` the file name and path are returned to the application
6. The application downloads the file from s3 and begins to sort and order the results.
7. The application checks the activity file results against the information stored in a DynamoDB table. If the data already exists in the dtabase, it is considered 'normal' to the behavior baseline. The records TTL is refreshed for another 90 days. If the event data is new (anomaly) it adds the record to the database with a 90 day TTL and enters into a possible alert condition.
8. If the role and actions meet the alert criteria the application builds a splunk payload and sends the `alert` to a SNS topic which triggers a Lambda function to sweep the results into Splunk or sends it directly to splunk depending on how it is configured.


### Lambda Structure
Below is the structure of the Lambda functions.
1. This is the muster function
2. SNS message 1 for each account
3. Discernment functions running on a per account basis.

![](lambda_flow.png)

## More indepth explaination

https://jellyparks.com/AWS/cloudtrail-anomaly-detection.html

## Original Inspiration

- https://www.youtube.com/watch?v=kWJoiZ9yMpg
- https://github.com/Netflix-Skunkworks/cloudtrail-anomaly

## Whats Next?

- I need to finish out alerting for the other identity types
- Account local functions vs centralized functions. I think this will help with some overall effciences. It does potentially make things a bit more complicated. Making sure they run everywhere, appropirate back billing, tamper protection, etc.

