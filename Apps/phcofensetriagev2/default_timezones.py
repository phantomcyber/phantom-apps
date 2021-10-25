# File: default_timezones.py
#
# Copyright (c) 2021 Cofense
#
# This unpublished material is proprietary to Cofense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Cofense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

"""
https://github.com/prefrontal/dateutil-parser-timezones

MIT License

Copyright (c) 2016 Craig Bennett

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from dateutil.tz import gettz


def timezones():
    """
    Handle different timezones.

    :return: timezones
    """
    timezones = {}

    timezones['ACDT'] = gettz('Australia/Darwin')
    timezones['ACST'] = gettz('Australia/Darwin')
    timezones['ACT'] = gettz('Brazil/Acre')
    timezones['ADT'] = gettz('America/Halifax')
    timezones['AEDT'] = gettz('Australia/Sydney')
    timezones['AEST'] = gettz('Australia/Sydney')
    timezones['AFT'] = gettz('Asia/Kabul')
    timezones['AKDT'] = gettz('America/Juneau')
    timezones['AKST'] = gettz('America/Juneau')
    timezones['AMST'] = gettz('America/Manaus')
    timezones['AMT'] = gettz('America/Manaus')
    timezones['ART'] = gettz('America/Cordoba')
    timezones['AST'] = gettz('Asia/Riyadh')
    timezones['AWST'] = gettz('Australia/Perth')
    timezones['AZOST'] = gettz('Atlantic/Azores')
    timezones['AZOT'] = gettz('Atlantic/Azores')
    timezones['AZT'] = gettz('Asia/Baku')
    timezones['BDT'] = gettz('Asia/Brunei')
    timezones['BIOT'] = gettz('Etc/GMT+6')
    timezones['BIT'] = gettz('Pacific/Funafuti')
    timezones['BOT'] = gettz('America/La_Paz')
    timezones['BRST'] = gettz('America/Sao_Paulo')
    timezones['BRT'] = gettz('America/Sao_Paulo')
    timezones['BST'] = gettz('Asia/Dhaka')
    timezones['BTT'] = gettz('Asia/Thimphu')
    timezones['CAT'] = gettz('Africa/Harare')
    timezones['CCT'] = gettz('Indian/Cocos')
    timezones['CDT'] = gettz('America/Chicago')
    timezones['CEST'] = gettz('Europe/Berlin')
    timezones['CET'] = gettz('Europe/Berlin')
    timezones['CHADT'] = gettz('Pacific/Chatham')
    timezones['CHAST'] = gettz('Pacific/Chatham')
    timezones['CHOST'] = gettz('Asia/Choibalsan')
    timezones['CHOT'] = gettz('Asia/Choibalsan')
    timezones['CHST'] = gettz('Pacific/Guam')
    timezones['CHUT'] = gettz('Pacific/Chuuk')
    timezones['CIST'] = gettz('Etc/GMT-8')
    timezones['CIT'] = gettz('Asia/Makassar')
    timezones['CKT'] = gettz('Pacific/Rarotonga')
    timezones['CLST'] = gettz('America/Santiago')
    timezones['CLT'] = gettz('America/Santiago')
    timezones['COST'] = gettz('America/Bogota')
    timezones['COT'] = gettz('America/Bogota')
    timezones['CST'] = gettz('America/Chicago')
    timezones['CT'] = gettz('Asia/Chongqing')
    timezones['CVT'] = gettz('Atlantic/Cape_Verde')
    timezones['CXT'] = gettz('Indian/Christmas')
    timezones['DAVT'] = gettz('Antarctica/Davis')
    timezones['DDUT'] = gettz('Antarctica/DumontDUrville')
    timezones['DFT'] = gettz('Europe/Berlin')
    timezones['EASST'] = gettz('Chile/EasterIsland')
    timezones['EAST'] = gettz('Chile/EasterIsland')
    timezones['EAT'] = gettz('Africa/Mogadishu')
    timezones['ECT'] = gettz('America/Guayaquil')
    timezones['EDT'] = gettz('America/New_York')
    timezones['EEST'] = gettz('Europe/Bucharest')
    timezones['EET'] = gettz('Europe/Bucharest')
    timezones['EGST'] = gettz('America/Scoresbysund')
    timezones['EGT'] = gettz('America/Scoresbysund')
    timezones['EIT'] = gettz('Asia/Jayapura')
    timezones['EST'] = gettz('America/New_York')
    timezones['FET'] = gettz('Europe/Minsk')
    timezones['FJT'] = gettz('Pacific/Fiji')
    timezones['FKST'] = gettz('Atlantic/Stanley')
    timezones['FKT'] = gettz('Atlantic/Stanley')
    timezones['FNT'] = gettz('Brazil/DeNoronha')
    timezones['GALT'] = gettz('Pacific/Galapagos')
    timezones['GAMT'] = gettz('Pacific/Gambier')
    timezones['GET'] = gettz('Asia/Tbilisi')
    timezones['GFT'] = gettz('America/Cayenne')
    timezones['GILT'] = gettz('Pacific/Tarawa')
    timezones['GIT'] = gettz('Pacific/Gambier')
    timezones['GMT'] = gettz('GMT')
    timezones['GST'] = gettz('Asia/Muscat')
    timezones['GYT'] = gettz('America/Guyana')
    timezones['HADT'] = gettz('Pacific/Honolulu')
    timezones['HAEC'] = gettz('Europe/Paris')
    timezones['HAST'] = gettz('Pacific/Honolulu')
    timezones['HKT'] = gettz('Asia/Hong_Kong')
    timezones['HMT'] = gettz('Indian/Kerguelen')
    timezones['HOVST'] = gettz('Asia/Hovd')
    timezones['HOVT'] = gettz('Asia/Hovd')
    timezones['ICT'] = gettz('Asia/Ho_Chi_Minh')
    timezones['IDT'] = gettz('Asia/Jerusalem')
    timezones['IOT'] = gettz('Etc/GMT+3')
    timezones['IRDT'] = gettz('Asia/Tehran')
    timezones['IRKT'] = gettz('Asia/Irkutsk')
    timezones['IRST'] = gettz('Asia/Tehran')
    timezones['IST'] = gettz('Asia/Kolkata')
    timezones['JST'] = gettz('Asia/Tokyo')
    timezones['KGT'] = gettz('Asia/Bishkek')
    timezones['KOST'] = gettz('Pacific/Kosrae')
    timezones['KRAT'] = gettz('Asia/Krasnoyarsk')
    timezones['KST'] = gettz('Asia/Seoul')
    timezones['LHST'] = gettz('Australia/Lord_Howe')
    timezones['LINT'] = gettz('Pacific/Kiritimati')
    timezones['MAGT'] = gettz('Asia/Magadan')
    timezones['MART'] = gettz('Pacific/Marquesas')
    timezones['MAWT'] = gettz('Antarctica/Mawson')
    timezones['MDT'] = gettz('America/Denver')
    timezones['MEST'] = gettz('Europe/Paris')
    timezones['MET'] = gettz('Europe/Berlin')
    timezones['MHT'] = gettz('Pacific/Kwajalein')
    timezones['MIST'] = gettz('Antarctica/Macquarie')
    timezones['MIT'] = gettz('Pacific/Marquesas')
    timezones['MMT'] = gettz('Asia/Rangoon')
    timezones['MSK'] = gettz('Europe/Moscow')
    timezones['MST'] = gettz('America/Denver')
    timezones['MUT'] = gettz('Indian/Mauritius')
    timezones['MVT'] = gettz('Indian/Maldives')
    timezones['MYT'] = gettz('Asia/Kuching')
    timezones['NCT'] = gettz('Pacific/Noumea')
    timezones['NDT'] = gettz('Canada/Newfoundland')
    timezones['NFT'] = gettz('Pacific/Norfolk')
    timezones['NPT'] = gettz('Asia/Kathmandu')
    timezones['NST'] = gettz('Canada/Newfoundland')
    timezones['NT'] = gettz('Canada/Newfoundland')
    timezones['NUT'] = gettz('Pacific/Niue')
    timezones['NZDT'] = gettz('Pacific/Auckland')
    timezones['NZST'] = gettz('Pacific/Auckland')
    timezones['OMST'] = gettz('Asia/Omsk')
    timezones['ORAT'] = gettz('Asia/Oral')
    timezones['PDT'] = gettz('America/Los_Angeles')
    timezones['PET'] = gettz('America/Lima')
    timezones['PETT'] = gettz('Asia/Kamchatka')
    timezones['PGT'] = gettz('Pacific/Port_Moresby')
    timezones['PHOT'] = gettz('Pacific/Enderbury')
    timezones['PKT'] = gettz('Asia/Karachi')
    timezones['PMDT'] = gettz('America/Miquelon')
    timezones['PMST'] = gettz('America/Miquelon')
    timezones['PONT'] = gettz('Pacific/Pohnpei')
    timezones['PST'] = gettz('America/Los_Angeles')
    timezones['PYST'] = gettz('America/Asuncion')
    timezones['PYT'] = gettz('America/Asuncion')
    timezones['RET'] = gettz('Indian/Reunion')
    timezones['ROTT'] = gettz('Antarctica/Rothera')
    timezones['SAKT'] = gettz('Asia/Vladivostok')
    timezones['SAMT'] = gettz('Europe/Samara')
    timezones['SAST'] = gettz('Africa/Johannesburg')
    timezones['SBT'] = gettz('Pacific/Guadalcanal')
    timezones['SCT'] = gettz('Indian/Mahe')
    timezones['SGT'] = gettz('Asia/Singapore')
    timezones['SLST'] = gettz('Asia/Colombo')
    timezones['SRET'] = gettz('Asia/Srednekolymsk')
    timezones['SRT'] = gettz('America/Paramaribo')
    timezones['SST'] = gettz('Asia/Singapore')
    timezones['SYOT'] = gettz('Antarctica/Syowa')
    timezones['TAHT'] = gettz('Pacific/Tahiti')
    timezones['TFT'] = gettz('Indian/Kerguelen')
    timezones['THA'] = gettz('Asia/Bangkok')
    timezones['TJT'] = gettz('Asia/Dushanbe')
    timezones['TKT'] = gettz('Pacific/Fakaofo')
    timezones['TLT'] = gettz('Asia/Dili')
    timezones['TMT'] = gettz('Asia/Ashgabat')
    timezones['TOT'] = gettz('Pacific/Tongatapu')
    timezones['TVT'] = gettz('Pacific/Funafuti')
    timezones['ULAST'] = gettz('Asia/Ulan_Bator')
    timezones['ULAT'] = gettz('Asia/Ulan_Bator')
    timezones['USZ1'] = gettz('Europe/Kaliningrad')
    timezones['UTC'] = gettz('UTC')
    timezones['UYST'] = gettz('America/Montevideo')
    timezones['UYT'] = gettz('America/Montevideo')
    timezones['UZT'] = gettz('Asia/Tashkent')
    timezones['VET'] = gettz('America/Caracas')
    timezones['VLAT'] = gettz('Asia/Vladivostok')
    timezones['VOLT'] = gettz('Europe/Volgograd')
    timezones['VOST'] = gettz('Antarctica/Vostok')
    timezones['VUT'] = gettz('Pacific/Efate')
    timezones['WAKT'] = gettz('Pacific/Wake')
    timezones['WAST'] = gettz('Africa/Lagos')
    timezones['WAT'] = gettz('Africa/Lagos')
    timezones['WEST'] = gettz('Europe/London')
    timezones['WET'] = gettz('Europe/London')
    timezones['WIT'] = gettz('Asia/Jakarta')
    timezones['WST'] = gettz('Australia/Perth')
    timezones['YAKT'] = gettz('Asia/Yakutsk')
    timezones['YEKT'] = gettz('Asia/Yekaterinburg')

    return timezones
