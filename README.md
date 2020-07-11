# cloudtrail-anomaly-serverless

## Overview

This repo contains a CloudTrail Anomaly detection serverless application. Its purpose is to examine cloudtrail logs for the past hour and compare them to a 90 day historical baseline by principalId. If there is a deviation is enters into an alert scenario. If the criteria is met to send an alert an event is sent to Splunk to trigger an alert.

The muster lambda function is designed to be split by business unit or some other organization structure which runs based on a cloudwatch cron event. This is designed to spread the load of the queries so that we are not overwhelming aws api calls for the account.

Each muster function calls the discernment function. Each account will have its own instance of the discernment script. This scirpt is designed to make the choice, is it an anomaly or not and then alert.

## More indepth explaination

https://jellyparks.com/AWS/cloudtrail_anomaly_detection.html

## Original Inspiration

- https://www.youtube.com/watch?v=kWJoiZ9yMpg
- https://github.com/Netflix-Skunkworks/cloudtrail-anomaly

