BASE_CONTAINER = {"tags": ["gib"]}
BASE_ARTIFACT = {
    "label": "gib indicator",
    "tags": ["gib"]
}

BASE_MAPPING_CONTAINER = {
    "source_data_identifier": "id",
    "sensitivity": "evaluation.tlp",
    "severity": "evaluation.severity"
}
BASE_MAPPING_ARTIFACT = {}

BASE_CEF_LIST = {
    "deviceVendor": "*Group IB",
    "deviceProduct": "*Threat Intelligence and Attribution",
    "deviceSeverity": "evaluation.severity"
}

BASE_CNC = {
    **BASE_CEF_LIST,
    "sourceHostName": "cnc.domain",
    "sourceAddress": "cnc.ipv4.ip",
    "requestUrl": "cnc.url",
    "deviceCustomString1": "cnc.ipv4.region",
    "deviceCustomString1label": "*region",
    "deviceCustomString2": "cnc.ipv4.countryName",
    "deviceCustomString2label": "*countryName",
    "deviceCustomString3": "cnc.ipv4.provider",
    "deviceCustomString3label": "*provider",
    "deviceCustomString4": "cnc.ipv4.city",
    "deviceCustomString4label": "*city",
    "deviceCustomString5": "cnc.ipv4.asn",
    "deviceCustomString5label": "*asn"
}

BASE_ADDITIONAL_INFO = {
    **BASE_CEF_LIST,
    "deviceCustomString1": "malware.name",
    "deviceCustomString1label": "*malwareName",
    "deviceCustomString2": "threatActor.name",
    "deviceCustomString2label": "*threatActor",
    "deviceCustomString3": "threatActor.isAPT",
    "deviceCustomString3label": "*threatActorIsApt",
    "requestUrl": "portalLink"
}

INCIDENT_COLLECTIONS_INFO = {
    'compromised/account': {
        "container": {
            "name": "login",
            "start_time": "dateDetected",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*cnc",
                    "type": "*network",
                    "start_time": "dateDetected",
                },
                "cef_list": BASE_CNC
            },
            {
                "artifact_list": {
                    "name": "*Compromised account",
                    "type": "*network",
                    "start_time": "dateDetected",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "login",
                    "deviceCustomString1label": "*login",
                    "deviceCustomString2": "password",
                    "deviceCustomString2label": "*password",
                    "destinationHostName": "domain",
                    "destinationAddress": "client.ipv4.ip"
                }
            },
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_ADDITIONAL_INFO,
                    "duser": "dropEmail.email",
                    "deviceCustomString4": "company",
                    "deviceCustomString4label": "*company",
                    "deviceCustomString5": "device",
                    "deviceCustomString5label": "*device",
                }
            }
        ],
        "prefix":
            "Compromised Account"
    },
    'compromised/breached': {
        "container": {
            "name": "email",
            "start_time": "uploadTime",
            "last_fetch": "updateTime"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Data breach",
                    "type": "*network",
                    "start_time": "uploadTime",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "leakName",
                    "deviceCustomString1label": "*leakName",
                    "deviceCustomString2": "password",
                    "deviceCustomString2label": "*password"
                }
            }
        ],
        "prefix":
            "Data Breach"
    },
    'compromised/card': {
        "container": {
            "name": "cardInfo.number",
            "start_time": "dateDetected",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*cnc",
                    "type": "*network",
                    "start_time": "dateDetected",
                },
                "cef_list": BASE_CNC
            },
            {
                "artifact_list": {
                    "name": "*Compromised card",
                    "type": "*other",
                    "start_time": "dateDetected",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "cardInfo.number",
                    "deviceCustomString1label": "*cardNumber",
                    "deviceCustomString2": "cardInfo.issuer.issuer",
                    "deviceCustomString2label": "*issuer",
                    "deviceCustomString3": "cardInfo.system",
                    "deviceCustomString3label": "*paymentSystem",
                    "deviceCustomString4": "cardInfo.type",
                    "deviceCustomString4label": "*type",
                    "deviceCustomString5": "cardInfo.validThru",
                    "deviceCustomString5label": "*validThru",
                    "deviceCustomNumber1": "cardInfo.cvv",
                    "deviceCustomNumber1label": "*cvv"
                }
            },
            {
                "artifact_list": {
                    "name": "*Owner",
                    "type": "*other"
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "owner.name",
                    "deviceCustomString1label": "*name",
                    "suser": "owner.email"
                }
            },
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_ADDITIONAL_INFO,
                    "deviceCustomString4": "company",
                    "deviceCustomString4label": "*company",
                }
            }
        ],
        "prefix":
            "Compromised Card",
    },
    'malware/targeted_malware': {
        "container": {
            "name": "md5",
            "start_time": "date",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Targeted malware",
                    "type": "*file",
                    "start_time": "date",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "fileName": "fileName",
                    "fileType": "fileType",
                    "fileSize": "size",
                    "deviceCustomString1": "injectMd5",
                    "deviceCustomString1label": "*injectMd5",
                    "deviceCustomString2": "md5",
                    "deviceCustomString2label": "*md5",
                    "deviceCustomString3": "sha1",
                    "deviceCustomString3label": "*sha1",
                    "deviceCustomString4": "sha256",
                    "deviceCustomString4label": "*sha256"
                }
            },
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_ADDITIONAL_INFO,
                    "deviceCustomString4": "source",
                    "deviceCustomString4label": "*source",
                    "deviceCustomString5": "company",
                    "deviceCustomString5label": "*company",
                }
            }
        ],
        "prefix":
            "Targeted Malware"
    },
    'osi/public_leak': {
        "container": {
            "name": "hash",
            "start_time": "created",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "fileHash": "hash",
                    "fileSize": "size",
                    "deviceCustomString1": "language",
                    "deviceCustomString1label": "*language",
                    "deviceCustomString2": "matches",
                    "deviceCustomString2label": "*matches",
                    "requestUrl": "portalLink"
                }
            }
        ],
        "prefix":
            "Public Leak"
    },
    'osi/git_leak': {
        "container": {
            "name": "name",
            "start_time": "dateDetected",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "fileName": "name",
                    "deviceCustomString1": "source",
                    "deviceCustomString1label": "*source",
                    "deviceCustomString2": "repository",
                    "deviceCustomString2label": "*repository",
                    "deviceCustomString3": "matchesType",
                    "deviceCustomString3label": "*matchesType",
                    "requestUrl": "file"
                }
            }
        ],
        "prefix":
            "Git Leak"
    },
    'bp/phishing': {
        "container": {
            "name": "phishingDomain.domain",
            "start_time": "dateDetected",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Phishing",
                    "type": "*network",
                    "start_time": "dateDetected",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "sourceHostName": "phishingDomain.domain",
                    "sourceAddress": "ipv4.ip",
                    "requestUrl": "url",
                    "deviceCustomString1": "ipv4.region",
                    "deviceCustomString1label": "*region",
                    "deviceCustomString2": "ipv4.countryName",
                    "deviceCustomString2label": "*countryName",
                    "deviceCustomString3": "ipv4.provider",
                    "deviceCustomString3label": "*provider",
                    "deviceCustomString4": "ipv4.city",
                    "deviceCustomString4label": "*city",
                    "deviceCustomString5": "ipv4.asn",
                    "deviceCustomString5label": "*asn",
                    "deviceCustomString6": "phishingDomain.title",
                    "deviceCustomString6label": "*phishingTitle"
                }
            },
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "company",
                    "deviceCustomString1label": "*company",
                    "deviceCustomString2": "status",
                    "deviceCustomString2label": "*status",
                    "deviceCustomString3": "objective",
                    "deviceCustomString3label": "*objective",
                    "deviceCustomString4": "targetBrand",
                    "deviceCustomString4label": "*targetBrand",
                    "deviceCustomString5": "targetCategory",
                    "deviceCustomString5label": "*targetCategory",
                    "deviceCustomString6": "targetDomain",
                    "deviceCustomString6label": "*targetDomain",
                    "requestUrl": "portalLink"
                }
            }
        ],
        "prefix":
            "Phishing"
    },
    'bp/phishing_kit': {
        "container": {
            "name": "hash",
            "start_time": "dateDetected",
            "end_time": "dateLastSeen",
            "last_fetch": "seqUpdate"
        },
        "artifacts": [
            {
                "artifact_list": {
                    "name": "*Phishing_kit",
                    "type": "*file",
                    "start_time": "dateDetected",
                    "end_time": "dateLastSeen"
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "fileHash": "hash",
                    "sourceDomain": "downloadedFrom.domain",
                    "requestUrl": "downloadedFrom.url",
                    "duser": "emails"
                }
            },
            {
                "artifact_list": {
                    "name": "*Additional info",
                    "type": "*other",
                },
                "cef_list": {
                    **BASE_CEF_LIST,
                    "deviceCustomString1": "company",
                    "deviceCustomString1label": "*company",
                    "deviceCustomString2": "source",
                    "deviceCustomString2label": "*source",
                    "deviceCustomString3": "login",
                    "deviceCustomString3label": "*login",
                    "deviceCustomString4": "targetBrand",
                    "deviceCustomString4label": "*targetBrand",
                    "requestUrl": "portalLink"
                }
            }
        ],
        "prefix":
            "Phishing Kit"
    }
}
GIB_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SPLUNK_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

BASE_MAX_CONTAINERS_COUNT = 100
BASE_MAX_ARTIFACTS_COUNT = 1000
