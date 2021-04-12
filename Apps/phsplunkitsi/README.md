# Phantom App for Splunk IT Service Intelligence

Author: Splunk Inc.
Latest Version Tag: 1.0.1
Date: 2020-06-10

This app integrates with Splunk IT Service Intelligence to provide operations on Splunk IT Service Intelligence episodes, services, entities, and object maintenance.

## Actions

* `test connectivity`: test connectivity to Splunk ITSI instance

### episode actions

* `get episode`: get Splunk ITSI episode information
* `update episode`: update status, severity, owner of a Splunk ITSI episode
* `break episode`: break a Splunk ITSI episode
* `close episode`: set status of a Splunk ITSI episode to closed and optionally break it
* `add episode comment`: add comment to Splunk ITSI episode
* `get episode events`: get latest events for Splunk ITSI episode
* `add episode ticket`: add ticketing information to Splunk ITSI episode
* `get episode tickets`: get ticketing information for Splunk ITSI episode

### service actions

* `get service`: get Splunk ITSI service information
* `get service entities`: get entities of a Splunk ITSI service
* `update service status`: set Splunk ITSI service status to enabled or disabled

### entity actions

* `get entity`: get Splunk ITSI entity information

### object maintenance actions

* `get maintenance window`: get Splunk ITSI maintenance window information
* `add maintenance window`: add Splunk ITSI maintenance window
* `update maintenance window`:  update Splunk ITSI maintenance window
* `end maintenance window`: end Splunk ITSI maintenance window now

---

## Release Notes

### Version: 1.0.0

#### Release Date: June 10, 2020

#### Compatibility

* Splunk IT Service Intelligence: 4.4
* Phantom: 4.8

#### Changes

* New action `test connectivity`

* New action `get episode`
* New action `update episode`
* New action `break episode`
* New action `close episode`
* New action `add episode comment`
* New action `get episode events`
* New action `add episode ticket`
* New action `get episode tickets`

* New action `get service`
* New action `get service entities`
* New action `update service status`

* New action `get entity`

* New action `get maintenance window`
* New action `add maintenance window`
* New action `update maintenance window`
* New action `end maintenance window`
