# File: fireeyeax_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Define your constants here
FIREEYEAX_API_PATH = "wsapis/v2.0.0/"
FIREEYEAX_LOGIN_ENDPOINT = "auth/login"
FIREEYEAX_LOGOUT_ENDPOINT = "auth/logout"
FIREEYEAX_ALERTS_ENDPOINT = "alerts"
FIREEYEAX_DETONATE_FILE_ENDPOINT = "submissions"
# Alterative Endpoint. Acts exactly the same as the submissions endpoint
# FIREEYEAX_DETONATE_FILE_ENDPOINT = "submissions/file"
FIREEYEAX_DETONATE_URL_ENDPOINT = "submissions/url"
FIREEYEAX_GET_STATUS_ENDPOINT = "submissions/status/{submission_id}"
FIREEYEAX_GET_RESULTS_ENDPOINT = "submissions/results/{submission_id}"
FIREEYEAX_SAVE_ARTIFACTS_ENDPOINT = "artifacts/{uuid}"
# FIREEYEAX_GET_CONFIG_ENDPOINT = "config"

# Application codes
# Application codes allow for the specific application to be used for the analysis
# At the time of writing this app these are all the code for my company's console
FIREEYEAX_APPLICATION_CODES = {
    "Auto": 0,
    "Adobe Acrobat Reader DC 15.008": "235",
    "Adobe Reader 10.0": "8",
    "Adobe Reader 10.1": "94",
    "Adobe Reader 11.0": "95",
    "Adobe Reader 11.0.01": "227",
    "Adobe Reader 7.0": "30",
    "Adobe Reader 8.0": "31",
    "Adobe Reader 9.0": "32",
    "Adobe Reader 9.4": "85",
    "CMSTP": "306",
    "CMSTP64": "307",
    "Chrome 26.0": "89",
    "Chrome 36.0": "185",
    "Chrome 40.0": "217",
    "Command Prompt": "99",
    "Firefox 17.0": "88",
    "Firefox 19.0": "157",
    "Firefox 38.0": "209",
    "Firefox 42.0": "220",
    "Generic 1.0": "296",
    "Hancom Handler 2018": "228",
    "IIS_Server64 1.0": "308",
    "Ichitaro 2013": "161",
    "InternetExplorer (64-bit) 11.0": "170",
    "InternetExplorer 10.0": "158",
    "InternetExplorer 11.0": "169",
    "InternetExplorer 6.0": "5",
    "InternetExplorer 7.0": "21",
    "InternetExplorer 8.0": "23",
    "InternetExplorer 9.0": "2",
    "InternetExplorer X": "104",
    "Java JDK JRE 7.13": "205",
    "Java JDK JRE 8.0": "178",
    "MS Access 2013": "290",
    "MS Excel 2003 SP2": "149",
    "MS Excel 2003 SP3": "152",
    "MS Excel 2007": "46",
    "MS Excel 2010 SP2": "202",
    "MS Excel 2013": "183",
    "MS Excel 2013 SP1": "223",
    "MS OneNote 2013": "291",
    "MS Outlook 2007": "50",
    "MS Outlook 2013": "184",
    "MS Outlook 2013 SP1": "226",
    "MS PowerPoint 2003 SP2": "150",
    "MS PowerPoint 2003 SP3": "153",
    "MS PowerPoint 2007": "48",
    "MS PowerPoint 2010 SP2": "203",
    "MS PowerPoint 2013": "189",
    "MS PowerPoint 2013 SP1": "225",
    "MS Publisher 2013": "284",
    "MS Publisher 2013 SP1": "285",
    "MS Word 2003 SP2": "148",
    "MS Word 2003 SP3": "151",
    "MS Word 2007": "44",
    "MS Word 2010 SP2": "201",
    "MS Word 2013": "188",
    "MS Word 2013 SP1": "224",
    "Microsoft Compiled HTML Help": "84",
    "Microsoft Edge (64-bit) 20.10240": "213",
    "Microsoft HTML Application Host 10.0": "239",
    "Microsoft HTML Application Host 11.0": "240",
    "Microsoft HTML Application Host 8.0": "238",
    "Microsoft Windows Help File": "86",
    "Multiple Adobe Reader X": "96",
    "Multiple MS Excel X": "155",
    "Multiple MS PowerPoint X": "156",
    "Multiple MS Word X": "154",
    "PHP WebShell 1.0": "293",
    "QuickTime Player 7.6": "15",
    "QuickTime Player 7.7": "111",
    "RealPlayer 12.0": "26",
    "RealPlayer 16.0": "112",
    "RegSVR 32.0": "295",
    "Regedit": "302",
    "RunDLL 1.0": "71",
    "Shellcode32 1.0": "303",
    "Shellcode64 1.0": "304",
    "VLC Media Player 2.0": "93",
    "VLC Media Player 2.1": "165",
    "WAB": "309",
    "WMIC 1.0": "297",
    "Windows Explorer": "57",
    "Windows Media Player 11.0": "29",
    "Windows Media Player 12.0": "67",
    "Windows PowerShell": "192",
    "Windows Scripting Host": "98",
    "XML Handler": "241",
    "XPS Viewer 1.0": "166"
}

# Exception message handling constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Fireeye AX Server. Please check the asset configuration and|or the action parameters"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"

# Parameter Keys
TIMEOUT_ACTION_PARAM = "'timeout' action parameter"
PROFILE_ACTION_PARAM = "'profile' action parameter"
URL_ACTION_PARAM = "'url' action parameter"
