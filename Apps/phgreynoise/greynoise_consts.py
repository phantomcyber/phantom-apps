# File: greynoise_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# URLs
API_KEY_CHECK_URL = "https://api.greynoise.io/ping"
LOOKUP_IP_URL = "https://api.greynoise.io/v2/noise/quick/{ip}"
VISUALIZATION_URL = "https://viz.greynoise.io/ip/{ip}"
IP_REPUTATION_URL = "https://api.greynoise.io/v2/noise/context/{ip}"
GNQL_QUERY_URL = "https://api.greynoise.io/v2/experimental/gnql"
LOOKUP_IPS_URL = "https://api.greynoise.io/v2/noise/multi/quick?ips={ips}"
RIOT_IP_URL = "https://api.greynoise.io/v2/riot/{ip}"
COMMUNITY_IP_URL = "https://api.greynoise.io/v3/community/{ip}"

CODES = {
    "0x00": "The IP has never been observed scanning the Internet",
    "0x01": "The IP has been observed by the GreyNoise sensor network",
    "0x02": "The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed",
    "0x03": "The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network",
    "0x04": "Reserved",
    "0x05": "This IP is commonly spoofed in Internet-scan activity",
    "0x06": "This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently",
    "0x07": "This IP is invalid",
    "0x08": "This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 60 days",
    "0x09": "IP was found in RIOT",
    "0x10": "IP has been observed by the GreyNoise sensor network and is in RIOT"
}

TRUST_LEVELS = {
    "1": "1 - Reasonably Ignore",
    "2": "2 - Commonly Seen"
}

SIZE_ACTION_PARAM = "'size' action parameter"
ONPOLL_SIZE_CONFIG_PARAM = "'on_poll_size' config parameter"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"
NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {key}"

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
INVALID_COMMA_SEPARATED_VALUE_ERR_MSG = "Please provide valid comma-seprated value in the '{key}' action parameter"
COMMUNITY_LIMIT_REACHED_MSG = "You have hit your daily rate limit of 100 requests per day. Please create a free account or upgrade your plan at https://greynoise.io/pricing."
