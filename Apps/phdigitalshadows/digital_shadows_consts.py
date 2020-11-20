#
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Must match json configuration object in digital_shadows.json
DS_API_KEY_CFG = 'ds_api_key'
DS_API_SECRET_KEY_CFG = 'ds_api_secret_key'

DS_ACTION_NOT_SUPPORTED = 'Action {} not supported'

DS_TEST_CONNECTIVITY_MSG = 'Testing Digital Shadows API Credentials: {}'
DS_TEST_CONNECTIVITY_MSG_PASS = 'Connectivity Test Passed'
DS_TEST_CONNECTIVITY_MSG_FAIL = 'Connectivity Test Failed'

DS_LOOKUP_USERNAME_SUCCESS = 'Digital Shadows username lookup successful'
DS_LOOKUP_USERNAME_NOT_FOUND = 'Username not found in Digital Shadows Breach database'

DS_POLL_BREACH_COMPLETE = 'Digital Shadows Breach {} ingested ({} of {})'

DS_POLL_INCIDENT_COMPLETE = 'Digital Shadows Incident {} ingested ({} of {})'

DS_GET_INCIDENT_SUCCESS = 'Digital Shadows incident fetched'
DS_GET_INCIDENT_NOT_FOUND = 'Incident not found in Digital Shadows'

DS_GET_INTELLIGENCE_INCIDENT_SUCCESS = 'Digital Shadows intel-incident fetched'
DS_GET_INTELLIGENCE_INCIDENT_NOT_FOUND = 'Intel-incident not found in Digital Shadows'

DS_GET_BREACH_SUCCESS = 'Digital Shadows data breaches fetched'
DS_GET_BREACH_NOT_FOUND = 'Data breach not found in Digital Shadows'

DS_GET_INFRASTRUCTURE_SUCCESS = 'Digital Shadows infrastructure ip-ports fetched'
DS_GET_INFRASTRUCTURE_NOT_FOUND = 'Infrastructure ip-ports not found in Digital Shadows'

DS_GET_INFRASTRUCTURE_SSL_SUCCESS = 'Digital Shadows infrastructure ssl fetched'
DS_GET_INFRASTRUCTURE_SSL_NOT_FOUND = 'Infrastructure ssl not found in Digital Shadows'

DS_GET_INFRASTRUCTURE_VULNERABILITIES_SUCCESS = 'Digital Shadows infrastructure Vulnerabilities fetched'
DS_GET_INFRASTRUCTURE_VULNERABILITIES_NOT_FOUND = 'Infrastructure Vulnerabilities not found in Digital Shadows'

DS_DL_SUBTYPE = ['CREDENTIAL_COMPROMISE', 'CUSTOMER_DETAILS', 'INTELLECTUAL_PROPERTY', 'INTERNALLY_MARKED_DOCUMENT']
DS_DL_SUBTYPE.extend(['LEGACY_MARKED_DOCUMENT', 'PROTECTIVELY_MARKED_DOCUMENT', 'TECHNICAL_LEAKAGE', 'UNMARKED_DOCUMENT'])
DS_BP_SUBTYPE = ['BRAND_MISUSE', 'DEFAMATION', 'MOBILE_APPLICATION', 'NEGATIVE_PUBLICITY', 'PHISHING_ATTEMPT', 'SPOOF_PROFILE']
DS_INFR_SUBTYPE = ['CVE', 'DOMAIN_CERTIFICATE_ISSUE', 'EXPOSED_PORT']
DS_PS_SUBTYPE = ['COMPANY_THREAT', 'EMPLOYEE_THREAT', 'PERSONAL_INFORMATION']
DS_SMC_SUBTYPE = ['CORPORATE_INFORMATION', 'PERSONAL_INFORMATION', 'TECHNICAL_INFORMATION']
