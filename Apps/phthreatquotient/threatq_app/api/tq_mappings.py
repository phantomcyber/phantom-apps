# Manually taken from /api/objects
threatq_objects = [
    {
        "name": "indicator",
        "display_name": "Indicator",
        "display_name_plural": "Indicators",
        "collection": "indicators",
        "types": [
            {
                "name": "ASN"
            },
            {
                "name": "Binary String"
            },
            {
                "name": "CIDR Block"
            },
            {
                "name": "CVE"
            },
            {
                "name": "Email Address"
            },
            {
                "name": "Email Attachment"
            },
            {
                "name": "Email Subject"
            },
            {
                "name": "File Mapping"
            },
            {
                "name": "File Path"
            },
            {
                "name": "Filename"
            },
            {
                "name": "FQDN"
            },
            {
                "name": "Fuzzy Hash"
            },
            {
                "name": "GOST Hash"
            },
            {
                "name": "Hash ION"
            },
            {
                "name": "IP Address"
            },
            {
                "name": "IPv6 Address"
            },
            {
                "name": "MAC Address"
            },
            {
                "name": "MD5"
            },
            {
                "name": "Mutex"
            },
            {
                "name": "Password"
            },
            {
                "name": "Registry Key"
            },
            {
                "name": "Service Name"
            },
            {
                "name": "SHA-1"
            },
            {
                "name": "SHA-256"
            },
            {
                "name": "SHA-384"
            },
            {
                "name": "SHA-512"
            },
            {
                "name": "String"
            },
            {
                "name": "x509 Serial"
            },
            {
                "name": "x509 Subject"
            },
            {
                "name": "URL"
            },
            {
                "name": "URL Path"
            },
            {
                "name": "User-agent"
            },
            {
                "name": "Username"
            },
            {
                "name": "X-Mailer"
            }
        ],
        "statuses": [
            {
                "id": 1,
                "name": "Active",
                "description": "Poses a threat and is being exported to detection tools."
            },
            {
                "id": 2,
                "name": "Expired",
                "description": "No longer poses a serious threat."
            },
            {
                "id": 3,
                "name": "Indirect",
                "description": "Associated to an active indicator or event (i.e. pDNS)."
            },
            {
                "id": 4,
                "name": "Review",
                "description": "Requires further analysis."
            },
            {
                "id": 5,
                "name": "Whitelisted",
                "description": "Poses NO risk and should never be deployed."
            }
        ]
    },
    {
        "name": "adversary",
        "display_name": "Adversary",
        "display_name_plural": "Adversaries",
        "collection": "adversaries"
    },
    {
        "name": "event",
        "display_name": "Event",
        "display_name_plural": "Events",
        "collection": "events",
        "types": [
            {
                "id": 8,
                "name": "Anonymization",
                "casing": None
            },
            {
                "id": 7,
                "name": "Command and Control",
                "casing": None
            },
            {
                "id": 11,
                "name": "Compromised PKI Certificate",
                "casing": None
            },
            {
                "id": 4,
                "name": "DoS Attack",
                "casing": None
            },
            {
                "id": 9,
                "name": "Exfiltration",
                "casing": None
            },
            {
                "id": 10,
                "name": "Host Characteristics",
                "casing": None
            },
            {
                "id": 13,
                "name": "Incident",
                "casing": None
            },
            {
                "id": 12,
                "name": "Login Compromise",
                "casing": None
            },
            {
                "id": 5,
                "name": "Malware",
                "casing": None
            },
            {
                "id": 14,
                "name": "Sighting",
                "casing": None
            },
            {
                "id": 1,
                "name": "Spearphish",
                "casing": None
            },
            {
                "id": 3,
                "name": "SQL Injection Attack",
                "casing": None
            },
            {
                "id": 6,
                "name": "Watchlist",
                "casing": None
            },
            {
                "id": 2,
                "name": "Watering Hole",
                "casing": None
            }
        ],
        "fields": {}
    },
    {
        "name": "attachment",
        "display_name": "Attachment",
        "display_name_plural": "Attachments",
        "collection": "attachments",
        "types": [
            {
                "id": 1,
                "name": "Cuckoo",
                "casing": None
            },
            {
                "id": 2,
                "name": "CrowdStrike Intelligence",
                "casing": None
            },
            {
                "id": 3,
                "name": "Early Warning and Indicator Notice (EWIN)",
                "casing": None
            },
            {
                "id": 4,
                "name": "FireEye Analysis",
                "casing": None
            },
            {
                "id": 5,
                "name": "FBI FLASH",
                "casing": None
            },
            {
                "id": 6,
                "name": "Generic Text",
                "casing": None
            },
            {
                "id": 7,
                "name": "Intelligence Whitepaper",
                "casing": None
            },
            {
                "id": 8,
                "name": "iSight Report",
                "casing": None
            },
            {
                "id": 9,
                "name": "iSight ThreatScape Intelligence Report",
                "casing": None
            },
            {
                "id": 10,
                "name": "JIB",
                "casing": None
            },
            {
                "id": 11,
                "name": "MAEC",
                "casing": None
            },
            {
                "id": 12,
                "name": "Malware Analysis Report",
                "casing": None
            },
            {
                "id": 13,
                "name": "Malware Initial Findings Report (MFIR)",
                "casing": None
            },
            {
                "id": 14,
                "name": "Malware Sample",
                "casing": None
            },
            {
                "id": 15,
                "name": "Packet Capture",
                "casing": None
            },
            {
                "id": 16,
                "name": "Palo Alto Networks WildFire XML",
                "casing": None
            },
            {
                "id": 17,
                "name": "PCAP",
                "casing": None
            },
            {
                "id": 18,
                "name": "PDF",
                "casing": None
            },
            {
                "id": 19,
                "name": "Private Industry Notification (PIN)",
                "casing": None
            },
            {
                "id": 20,
                "name": "Spearphish Attachment",
                "casing": None
            },
            {
                "id": 21,
                "name": "STIX",
                "casing": None
            },
            {
                "id": 22,
                "name": "ThreatAnalyzer Analysis",
                "casing": None
            },
            {
                "id": 23,
                "name": "ThreatQ CSV File",
                "casing": None
            },
            {
                "id": 24,
                "name": "Whitepaper",
                "casing": None
            }
        ]
    },
    {
        "name": "signature",
        "display_name": "Signature",
        "display_name_plural": "Signatures",
        "collection": "signatures",
        "types": [
            {
                "id": 1,
                "name": "Bro",
                "casing": None
            },
            {
                "id": 2,
                "name": "Custom",
                "casing": None
            },
            {
                "id": 3,
                "name": "Cybox",
                "casing": None
            },
            {
                "id": 4,
                "name": "OpenIOC",
                "casing": None
            },
            {
                "id": 5,
                "name": "Regex",
                "casing": None
            },
            {
                "id": 6,
                "name": "Snort",
                "casing": None
            },
            {
                "id": 7,
                "name": "STIX Indicator Pattern",
                "casing": None
            },
            {
                "id": 8,
                "name": "YARA",
                "casing": None
            }
        ],
        "statuses": [
            {
                "id": 1,
                "name": "Active"
            },
            {
                "id": 2,
                "name": "Expired"
            },
            {
                "id": 3,
                "name": "Indirect"
            },
            {
                "id": 4,
                "name": "Non-malicious"
            },
            {
                "id": 5,
                "name": "Review"
            },
            {
                "id": 6,
                "name": "Whitelisted"
            }
        ]
    },
    {
        "name": "task",
        "display_name": "Task",
        "display_name_plural": "Tasks",
        "collection": "tasks",
        "statuses": [
            {
                "id": 1,
                "name": "To Do"
            },
            {
                "id": 2,
                "name": "In Progress"
            },
            {
                "id": 3,
                "name": "Review"
            },
            {
                "id": 4,
                "name": "Done"
            }
        ]
    },
    {
        "name": "campaign",
        "display_name": "Campaign",
        "display_name_plural": "Campaigns",
        "collection": "campaign",
        "types": [],
        "statuses": []
    },
    {
        "name": "course_of_action",
        "display_name": "Course of Action",
        "display_name_plural": "Courses of Action",
        "collection": "course_of_action",
        "types": [],
        "statuses": []
    },
    {
        "name": "exploit_target",
        "display_name": "Exploit Target",
        "display_name_plural": "Exploit Targets",
        "collection": "exploit_target",
        "types": [],
        "statuses": []
    },
    {
        "name": "incident",
        "display_name": "Incident",
        "display_name_plural": "Incidents",
        "collection": "incident",
        "types": [],
        "statuses": []
    },
    {
        "id": 5,
        "name": "ttp",
        "display_name": "TTP",
        "display_name_plural": "TTPs",
        "collection": "ttp",
        "types": [],
        "statuses": []
    },
    {
        "name": "attack_pattern",
        "display_name": "Attack Pattern",
        "display_name_plural": "Attack Patterns",
        "collection": "attack_pattern",
        "types": [],
        "statuses": []
    },
    {
        "name": "identity",
        "display_name": "Identity",
        "display_name_plural": "Identities",
        "collection": "identity",
        "types": [],
        "statuses": []
    },
    {
        "name": "intrusion_set",
        "display_name": "Intrusion Set",
        "display_name_plural": "Intrusion Sets",
        "collection": "intrusion_set",
        "types": [],
        "statuses": []
    },
    {
        "name": "malware",
        "display_name": "Malware",
        "display_name_plural": "Malware",
        "collection": "malware",
        "types": [],
        "statuses": []
    },
    {
        "name": "report",
        "display_name": "Report",
        "display_name_plural": "Reports",
        "collection": "report",
        "types": [],
        "statuses": []
    },
    {
        "name": "tool",
        "display_name": "Tool",
        "display_name_plural": "Tools",
        "collection": "tool",
        "types": [],
        "statuses": []
    },
    {
        "name": "vulnerability",
        "display_name": "Vulnerability",
        "display_name_plural": "Vulnerabilities",
        "collection": "vulnerability",
        "types": [],
        "statuses": []
    }
]

typed_objects = ["indicators", "events", "signatures"]
statused_objects = ["indicators", "signatuers", "attachments"]
object_types = [
    "adversaries",
    "attack_pattern",
    "campaign",
    "course_of_action",
    "events",
    "exploit_target",
    "identity",
    "incident",
    "indicators",
    "intrusion_set",
    "malware",
    "report",
    "signatures",
    "tool",
    "ttp",
    "vulnerability"
]
