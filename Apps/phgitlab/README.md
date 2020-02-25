# GitLab Phantom App

This app connects a GitLab instance with Splunk>Phantom instance. The GitLab App for Phantom allows playbooks to implement the following actions from the [GitLab API](https://docs.gitlab.com/ee/api/api_resources.html):

* [get users](https://docs.gitlab.com/ee/api/users.html#for-normal-users)
* [get projects](https://docs.gitlab.com/ee/api/projects.html#list-all-projects)
* [get branches](https://docs.gitlab.com/ee/api/branches.html#list-repository-branches)
* [create project trigger](https://docs.gitlab.com/ee/api/pipeline_triggers.html#create-a-project-trigger)
* [list project triggers](https://docs.gitlab.com/ee/api/pipeline_triggers.html#list-project-triggers)
* [trigger pipeline](https://docs.gitlab.com/ee/ci/triggers/#triggering-a-pipeline)

## Prerequisites

* The version of the Splunk>Phantom instance is running at least version `4.515922`
* Access to a GitLab instance running at least version `11.11.3` and a user's access token
* If using the `trigger pipeline` action, [a GitLab runner](https://docs.gitlab.com/runner/install/linux-manually.html) has been deployed and registered to the relevant GitLab project

## LICENSE

File: README.md
Copyright (c) Peter Bertel, 2020
Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
