# File: cloudflare_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# API Endpoints
CLOUDFLARE_ZONES_ENDPOINT = 'zones'
CLOUDFLARE_FWRULE_ENDPOINT = 'zones/{zone_id}/firewall/rules'
CLOUDFLARE_FILTERS_ENDPOINT = 'zones/{zone_id}/filters'
# CLOUDFLARE_SINGLE_FWRULE_ENDPOINT = 'zones/{zone_id}/firewall/rules/{rule_id}'

# Other constants
CLOUDFLARE_FILTER_RULE_IP = '(ip.src eq {ip})'
CLOUDFLARE_FILTER_RULE_UA = '(http.user_agent eq "{ua}") or (http.user_agent contains "{ua}")'

CLOUDFLARE_DUPLICATES_ERRCODE = 10102
CLOUDFLARE_VALID_ACTIONS = {'allow': True, 'block': False}

# Error messages
CLOUDFLARE_INVALID_ACTION_ERR = 'Unknown action "{action}". Supported values are [' + ', '.join(
    CLOUDFLARE_VALID_ACTIONS) + ']'
