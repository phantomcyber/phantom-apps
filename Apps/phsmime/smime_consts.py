# File: smime_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
SMIME_SIGN_PROGRESS_MSG = "Signing email message"
SMIME_SIGN_OK_MSG = "Email message signed successfully"
SMIME_SIGN_ERR_MSG = "Error occurred when signing message. Error: {err}"

SMIME_VERIFY_PROGRESS_MSG = "Verifying signed email message"
SMIME_VERIFY_OK_MSG = "Signed email message verified successfully"
SMIME_VERIFY_ERR_MSG = "Error occurred when verifying message. Error: {err}"
SMIME_VERIFY_ERR2_MSG = "Message received was not signed"

SMIME_ENCRYPT_PROGRESS_MSG = "Encrypting email message"
SMIME_ENCRYPT_OK_MSG = "Email message encrypted successfully"
SMIME_ENCRYPT_ERR_MSG = "Error occurred when encrypting message. Error: {err}"

SMIME_DECRYPT_PROGRESS_MSG = "Decrypting encrypted email message"
SMIME_DECRYPT_ERR_MSG = "Error occurred when decrypting message. Error: {err}"
SMIME_DECRYPT_ERR2_MSG = "Message received was not encrypted"
SMIME_DECRYPT_OK_MSG = "Email message decrypted successfully"
