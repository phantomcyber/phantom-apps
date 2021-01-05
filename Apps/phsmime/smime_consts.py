# File: smime_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Sign email action related constants
SMIME_SIGN_PROGRESS_MSG = "Signing email message"
SMIME_SIGN_OK_MSG = "Email message signed successfully"
SMIME_SIGN_ERR_MSG = "Error occurred while signing message. {err}"

# Verify email action related constants
SMIME_VERIFY_PROGRESS_MSG = "Verifying signed email message"
SMIME_VERIFY_OK_MSG = "Signed email message verified successfully"
SMIME_VERIFY_ERR_MSG = "Error occurred while verifying message. {err}"
SMIME_VERIFY_ERR2_MSG = "The received message was not signed"

# Encrypt email action related constants
SMIME_ENCRYPT_PROGRESS_MSG = "Encrypting email message"
SMIME_ENCRYPT_OK_MSG = "Email message encrypted successfully"
SMIME_ENCRYPT_ERR_MSG = "Error occurred while encrypting message. {err}"

# Decrypt email action related constants
SMIME_DECRYPT_PROGRESS_MSG = "Decrypting encrypted email message"
SMIME_DECRYPT_ERR_MSG = "Error occurred while decrypting message. {err}"
SMIME_DECRYPT_ERR2_MSG = "The received message was not encrypted"
SMIME_DECRYPT_OK_MSG = "Email message decrypted successfully"

# Error message handling constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the SMime Server. Please check the asset configuration and|or the action parameters"
