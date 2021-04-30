# File: vmray_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
VMRAY_JSON_SERVER = "vmray_server"
VMRAY_JSON_API_KEY = "vmray_api_key"
VMRAY_JSON_DISABLE_CERT = "disable_cert_verification"
VMRAY_ERR_SERVER_CONNECTION = "Could not connect to server. {}"
VMRAY_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
VMRAY_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
VMRAY_ERR_UNSUPPORTED_HASH = "Unsupported hash"
VMRAY_ERR_SAMPLE_NOT_FOUND = "Could not find sample"
VMRAY_ERR_OPEN_ZIP = "Could not open zip file"
VMRAY_ERR_ADD_VAULT = "Could not add file to vault"
VMRAY_ERR_MULTIPART = "File is a multipart sample. Multipart samples are not supported"
VMRAY_ERR_MALFORMED_ZIP = "Malformed zip"
VMRAY_ERR_SUBMIT_FILE = "Could not submit file"
VMRAY_ERR_GET_SUBMISSION = "Could not get submission"
VMRAY_ERR_SUBMISSION_NOT_FINISHED = "Submission is not finished"
VMRAY_ERR_NO_SUBMISSIONS = "Sample has no submissions"
VMRAY_ERR_FILE_EXISTS = "File already exists"
VMRAY_ERR_REST_API = "REST API Error"
VMRAY_ERR_CODE_MSG = "Error code unavailable"
VMRAY_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
VMRAY_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
VMRAY_ERR_SERVER_RES = "Error processing server response. {}"
VMRAY_INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
VMRAY_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

ACTION_ID_VMRAY_GET_FILE = "get_file"
ACTION_ID_VMRAY_DETONATE_FILE = "detonate_file"
ACTION_ID_VMRAY_DETONATE_URL = "detonate_url"
ACTION_ID_VMRAY_GET_REPORT = "get_report"
ACTION_ID_VMRAY_GET_INFO = "get_info"

VMRAY_DEFAULT_PASSWORD = b"infected"
DEFAULT_TIMEOUT = 60 * 10

VMRAY_SEVERITY_NOT_SUSPICIOUS = "not_suspicious"
VMRAY_SEVERITY_SUSPICIOUS = "suspicious"
VMRAY_SEVERITY_MALICIOUS = "malicious"
VMRAY_SEVERITY_BLACKLISTED = "blacklisted"
VMRAY_SEVERITY_WHITELISTED = "whitelisted"
VMRAY_SEVERITY_UNKNOWN = "unknown"
VMRAY_SEVERITY_ERROR = "error"

SAMPLE_TYPE_MAPPING = {
    "Apple Script": "apple script",
    "Archive": "archive",
    "CFB File": "compound binary file",
    "Email (EML)": "email",
    "Email (MSG)": "email",
    "Excel Document": "xls",
    "HTML Application": "html application",
    "HTML Application (Shell Link)": "html application",
    "HTML Document": "html document",
    "Hanword Document": "hanword document",
    "JScript": "jscript",
    "Java Archive": "jar",
    "Java Class": "java class",
    "macOS App": "macos app",
    "macOS Executable": "macos executable",
    "macOS PKG": "macos installer",
    "MHTML Document": "mhtml document",
    "MSI Setup": "msi",
    "Macromedia Flash": "flash",
    "Microsoft Access Database": "mdb",
    "Microsoft Project Document": "mpp",
    "Microsoft Publisher Document": "pub",
    "Microsoft Visio Document": "vsd",
    "PDF Document": "pdf",
    "PowerShell Script": "powershell",
    "PowerShell Script (Shell Link)": "powershell",
    "Powerpoint Document": "ppt",
    "Python Script": "python script",
    "RTF Document": "rtf",
    "Shell Script": "shell script",
    "URL": "url",
    "VBScript": "vbscript",
    "Windows ActiveX Control (x86-32)": "pe file",
    "Windows ActiveX Control (x86-64)": "pe file",
    "Windows Batch File": "batch file",
    "Windows Batch File (Shell Link)": "batch file",
    "Windows DLL (x86-32)": "dll",
    "Windows DLL (x86-64)": "dll",
    "Windows Driver (x86-32)": "pe file",
    "Windows Driver (x86-64)": "pe file",
    "Windows Exe (Shell Link)": "pe file",
    "Windows Exe (x86-32)": "pe file",
    "Windows Exe (x86-64)": "pe file",
    "Windows Help File": "windows help file",
    "Windows Script File": "windows script file",
    "Word Document": "doc",
}
