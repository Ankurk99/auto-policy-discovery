#!/bin/bash

export KNOX_AUTO_HOME=`dirname $(realpath "$0")`/..

# database info
export DB_DRIVER=mysql
export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_USER=root
export DB_PASS=password
export DB_NAME=flow_management

# database table info
export TB_NETWORK_FLOW=network_flow
export TB_DISCOVERED_POLICY=discovered_policy
export TB_CONFIGURATION=auto_policy_config

# cilium hubble info (if want to connect with hubble relay directly)
export HUBBLE_URL=127.0.0.1
export HUBBLE_PORT=4245

# operation mode: cronjob: 1
#                 onetime job: 2
export OPERATION_MODE=2
export CRON_JOB_TIME_INTERVAL="@every 0h0m5s"

# available network log source: hubble | db
export NETWORK_LOG_FROM=db
export DISCOVERED_POLICY_TO="db|file"
export POLICY_DIR=$KNOX_AUTO_HOME/policies/

# available discovery modes: 
#   all (egress+ingress): 3
#   egress only: 1
#   ingress only: 2
export DISCOVERY_POLICY_TYPES=3
export DISCOVERY_RULE_TYPES=511

# skip namepsace info
export IGNORING_NAMESPACES="kube-system|knox-auto-policy|cilium|hipster"

$KNOX_AUTO_HOME/src/knoxAutoPolicy