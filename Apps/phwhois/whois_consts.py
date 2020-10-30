# File: whois_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Json keys
WHOIS_ERR_QUERY = "Whois query failed"
WHOIS_SUCC_QUERY = "Whois query successful"
WHOIS_SUCC_QUERY_RETURNED_NO_REGISTRANT_DATA = "it did not return 'registrant' information in the 'contacts' data"
WHOIS_ERR_QUERY_RETURNED_NO_DATA = "Whois query did not return any information"
WHOIS_ERR_QUERY_RETURNED_NO_CONTACTS_DATA = "it did not return any information about 'admin', 'tech', 'registrant', 'billing' in the 'contacts' data"
WHOIS_ERR_PARSE_REPLY = "Unable to parse whois response"
WHOIS_ERR_PARSE_INPUT = "Unable to parse input data"
WHOIS_ERR_INVALID_DOMAIN = "Input does not seem to be a valid domain"

WHOIS_JSON_ASN_REGISTRY = "registry"
WHOIS_JSON_ASN = "asn"
WHOIS_JSON_COUNTRY_CODE = "country_code"
WHOIS_JSON_NETS = "nets"
WHOIS_JSON_SUBDOMAINS = "subdomains"
WHOIS_JSON_CACHE_UPDATE_TIME = "cache_update_time"
WHOIS_JSON_CACHE_EXP_DAYS = "update_days"
