[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
The asset settings page has several ingestions related settings. This app is currently written to
support the ingestion of either the Cofense Triage Threat Indicators or the Cofense Triage Reports.
This is set by the **ingestion_method** variable by a pull-down menu. If you wish to ingest both
sets of data, it is suggested you set up a second Cofense Triage asset with the same credentials,
but with the variable set to the other value.

**1. Remaining Settings**

<table>
<thead>
<tr class="header">
<th>Setting</th>
<th>Description</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>max_results</td>
<td>Maximum number of results retrieved during the ingestion run.</td>
<td>This is adjustable to any number. The practical limit is dictated by the number of API calls that your rate limit allows. Each API call will retrieve the maximum allowed of 50 results.</td>
</tr>
<tr class="even">
<td>start_date</td>
<td>The initial start date and time of the ingestion. The default is six days ago.</td>
<td>This setting is used only if there weren't any prior successful ingestions and were ignored afterward. If left blank, it will default to the product setting of six days ago. If one or more results are successfully ingested, the relevant date of the last ingested result is used to set the start date for the next ingestion run. It is important to set this setting to date within a range that contains data.<br />
</td>
</tr>
<tr class="odd">
<td>date_sort</td>
<td>Retrieve either the oldest results first or the latest results first.</td>
<td>This setting is used to set which pages of results to retrieve and how they are sorted. This setting makes the observed assumption that the result ID is ordered by ascending date. ie. ID=1 is an older result than ID=2. If this setting is the <strong>Oldest first</strong> the results are retrieved and sorted with the lowest ID first. If the ingestion run of <strong>max_results</strong> does not completely exhaust this list of results, it will continue to retrieve the oldest entries until all the results are exhausted. If this setting is the <strong>latest first</strong> the results are retrieved and sorted with the highest ID first. We will ingest the newest results first and then work our way down to older results until we hit <strong>max_results</strong> or your rate limit. <em>If older results remaining in the ingestion run, they will be ignored on the next ingestion run.</em> This will always guarantee your latest results are ingested first at the risk of losing older results if it exceeds your <strong>max_result</strong> or rate limit.</td>
</tr>
<tr class="even">
<td>cef_mapping</td>
<td>JSON dictionary is represented as a serialized JSON string. Only applicable if ingesting new artifacts</td>
<td>This parameter is a JSON dictionary represented as a serialized JSON string, such as the result of json.dumps(). Each key in the dictionary is a potential key name in an artifact that is to be renamed to the value. For example, if the cef_mapping is {"website": "requestURL"} your artifact will have requestURL cef fields in place of website cef fields.</td>
</tr>
<tr class="odd">
<td>ingestion_method</td>
<td>Ingestion of either Threat Indicators or Reports</td>
<td>User can select whether to ingest Threat Indicators or Reports</td>
</tr>
</tbody>
</table>

  

**2. Ingestion Settings for Ingesting Threat Indicators**

| Setting      | Description                                                                                                          | Notes                                                                                                                                                                                                                          |
|--------------|----------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| threat_type  | Filter results by threat indicator type, default retrieve All. Types are; Subject, Sender, Domain, URL, MD5, SHA256. | These are applied as filters in the API call to retrieved results. You may retrieve all results or filter results by a single type. At the moment, if you wish to ingest two types, it is suggested you create a second asset. |
| threat_level | Filter results by threat indicator level, default retrieve All. Levels are; Malicious, Suspicious, Benign.           | Similar to the threat_type setting, these will allow either all results or filtered to a single level.                                                                                                                         |

  

**3. Ingestion Settings for Ingesting Reports**

| Setting                 | Description                                                                                                                          | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                         |                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| report_type             | Type of reports to retrieve, default retrieve All.                                                                                   | Possible values are; All - All reports in Inbox, Recon, and Processed folders; Inbox - Uncategorized reports in the Inbox and Recon folders; Processed - Categorized reports in the Processed folder. Be aware that the reports in the Recon folder are ingested only if the option is All or Inbox but not Processed. Reports from the Inbox folder are unreviewed reports and therefore missing any evaluated information                                              |
| report_ingest_subfields | Only applicable if ingesting reports. This option will ingest the dictionary and list fields of the subject as additional artifacts. | If set to true, during ingestion of reports, in addition to the Report Artifact which contains the entire report as an artifact, it will extract various sub-elements and create individual artifacts for the following items; URLs, tags, rules, and attachments.                                                                                                                                                                                                       |
| report_match_priority   | The highest match priority is based on rule hits for the report.                                                                     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| report_category_id      | Filter by category ID, default retrieve All.                                                                                         | The category ID (1-5) for processed reports. Takes either string or number. Only valid when retrieving "All" or "Processed" reports. Category IDs correspond to category names as follows: 5 (lowest): Phishing Simulation; 1: Non-Malicious; 2: Spam; 3: Crimeware; 4 (highest): Advanced Threats. You may retrieve all results or filter results by a single category. At the moment, if you wish to ingest two categories, it is suggested you create a second asset. |
| report_tags             | One or more tags of processed reports to filter on. Use commas to separate multiple tags.                                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

**NOTE** : The Triage devices fetch data according to their own rules. If you look carefully at the
logs or the output of the poll-now, you may see the last result from the previous ingestion,
reingested and marked as a duplicate container. This is to guarantee we do not miss any results
since the last ingestion.
