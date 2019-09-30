# --
# File: haveibeenpwned_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

HAVEIBEENPWNED_API_BASE_URL = "https://haveibeenpwned.com/api/v2/"
HAVEIBEENPWNED_API_ENDPOINT_LOOKUP_EMAIL = "breachedaccount/{email}"
HAVEIBEENPWNED_API_ENDPOINT_LOOKUP_DOMAIN = "breaches"
HAVEIBEENPWNED_ACTION_PARAM_EMAIL = "email"
HAVEIBEENPWNED_ACTION_PARAM_DOMAIN = "domain"
HAVEIBEENPWEND_PARAM_DOMAIN_KEY = "domain"
HAVEIBEENPWNED_REST_CALL_ERR = "Error during REST call occurred"
HAVEIBEENPWNED_LOOKUP_DOMAIN_SUCCESS = "Lookup Domain succeeded"
HAVEIBEENPWNED_LOOKUP_EMAIL_SUCCESS = "Lookup Email succeeded"
HAVEIBEENPWNED_REST_CALL_FAILURE = "REST call failed"
HAVEIBEENPWNED_REST_CALL_JSON_FAILURE = "Conversion of Response to JSON failed"
HAVEIBEENPWNED_BAD_RESPONSE_CODES = {400: "Bad Request - the account does not comply with an acceptable format",
                                     403: "Forbidden - no user agent has been specified in the request",
                                     404: "Not found - The account could not be found and has likely not been pwned",
                                     429: "Too many requests - the rate limit has been exceeded"}
HAVEIBEENPWNED_STATUS_CODE_NO_DATA = 404
HAVEIBEENPWNED_TOTAL_BREACHES = "total_breaches"
