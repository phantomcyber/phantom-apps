# File: whois_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
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

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_UNAVAILABLE = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the server. Please check the asset configuration and|or the action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the '{}' parameter"
INVALID_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-zero positive integer value in the '{}' parameter"

# Regexes
REGISTRANT_REGEXES = [
    "(?:Registrant ID:(?P<handle>.+)\n)?(?:Registrant Name:(?P<name>.*)\n)?Registrant Organization:(?P<organization>.*)\n(?:Registrant Street1?:(?P<street1>.*)\n)?(?:Registrant Street2:(?P<street2>.*)\n)?(?:Registrant Street3:(?P<street3>.*)\n)?(?:Registrant City:(?P<city>.*)\n)?Registrant State/Province:(?P<state>.*)\n(?:Registrant Postal Code:(?P<postalcode>.*)\n)?Registrant Country:(?P<country>.*)\n(?:Registrant Phone:(?P<phone>.*)\n)?(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant Email:(?P<email>.*)",  # noqa: E501
    "Owner contact:\n      Organization:(?P<organization>.*)\n      Name:(?P<name>.*)\n      Address:(?P<street>.*)\n      Zipcode:(?P<postalcode>.*)\n      City:(?P<city>.*)\n      State:(?P<state>.*)\n      Country:(?P<country>.*)\n      Phone:(?P<phone>.*)\n      Fax:(?P<fax>.*)\n      E-mail:(?P<email>.*)\n\n"  # noqa: E501
]

TECH_CONTACT_REGEXES = [
    "(?:Tech ID:(?P<handle>.+)\n)?(?:Tech Name:(?P<name>.*)\n)?Tech Organization:(?P<organization>.*)\n(?:Tech Street1?:(?P<street1>.*)\n)?(?:Tech Street2:(?P<street2>.*)\n)?(?:Tech Street3:(?P<street3>.*)\n)?(?:Tech City:(?P<city>.*)\n)?Tech State/Province:(?P<state>.*)\n(?:Tech Postal Code:(?P<postalcode>.*)\n)?Tech Country:(?P<country>.*)\n(?:Tech Phone:(?P<phone>.*)\n)?(?:Tech Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech FAX:(?P<fax>.*)\n)?(?:Tech FAX Ext.:(?P<fax_ext>.*)\n)?Tech Email:(?P<email>.*)",  # noqa: E501
    "Tech contact:\n      Organization:(?P<organization>.*)\n      Name:(?P<name>.*)\n      Address:(?P<street>.*)\n      Zipcode:(?P<postalcode>.*)\n      City:(?P<city>.*)\n      State:(?P<state>.*)\n      Country:(?P<country>.*)\n      Phone:(?P<phone>.*)\n      Fax:(?P<fax>.*)\n      E-mail:(?P<email>.*)\n\n"  # noqa: E501
]

ADMIN_CONTACT_REGEXES = [
    "(?:Admin ID:(?P<handle>.+)\n)?(?:Admin Name:(?P<name>.*)\n)?Admin Organization:(?P<organization>.*)\n(?:Admin Street1?:(?P<street1>.*)\n)?(?:Admin Street2:(?P<street2>.*)\n)?(?:Admin Street3:(?P<street3>.*)\n)?(?:Admin City:(?P<city>.*)\n)?Admin State/Province:(?P<state>.*)\n(?:Admin Postal Code:(?P<postalcode>.*)\n)?Admin Country:(?P<country>.*)\n(?:Admin Phone:(?P<phone>.*)\n)?(?:Admin Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin FAX:(?P<fax>.*)\n)?(?:Admin FAX Ext.:(?P<fax_ext>.*)\n)?Admin Email:(?P<email>.*)",  # noqa: E501
    "Admin contact:\n      Organization:(?P<organization>.*)\n      Name:(?P<name>.*)\n      Address:(?P<street>.*)\n      Zipcode:(?P<postalcode>.*)\n      City:(?P<city>.*)\n      State:(?P<state>.*)\n      Country:(?P<country>.*)\n      Phone:(?P<phone>.*)\n      Fax:(?P<fax>.*)\n      E-mail:(?P<email>.*)\n\n"  # noqa: E501
]

BILLING_CONTACT_REGEXES = [
    "Billing contact:\n      Organization:(?P<organization>.*)\n      Name:(?P<name>.*)\n      Address:(?P<street>.*)\n      Zipcode:(?P<postalcode>.*)\n      City:(?P<city>.*)\n      State:(?P<state>.*)\n      Country:(?P<country>.*)\n      Phone:(?P<phone>.*)\n      Fax:(?P<fax>.*)\n      E-mail:(?P<email>.*)\n\n"  # noqa: E501
]
