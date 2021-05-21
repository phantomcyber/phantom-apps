# Contributing to Phantom

Thank you for considering spending your time contributing to Phantom Apps. Whether you're interested in bug-hunting, documentation, or creating entirely new apps, this document will help and guide you through the process.

If you've stumbled upon the site but don't know who or what we are, please check out the links below:
- [Splunk > Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html) - Home Page of Phantom
- [Phantom Community](https://my.phantom.us) - Phantom Community site

---

## First Steps
Make sure you have a [GitHub Account](https://www.github.com)
- Make sure you know how Git works.
    - [Git Book](https://git-scm.com/book/en/v2)
    - [Git Handbook](https://guides.github.com/introduction/git-handbook/)
    - [GitHub Git Guide](https://help.github.com/en/articles/git-and-github-learning-resources)
    - [Git Workflow](https://guides.github.com/introduction/flow/)
    - [Git Visualization](http://git-school.github.io/visualizing-git/) -> Super cool!

## Project Details
To successfully contribute, you should spend a little time familiarizing yourself with the following key topics.

- [Coding & Conventions](https://github.com/phantomcyber/phantom-apps/blob/next/.github/CONVENTIONS.md) - How we expect to see code formatted and apps named
- [Certified vs Standard App](https://github.com/phantomcyber/phantom-apps/blob/master/.github/CERTIFIED_V_UNCERTIFIED.md) definitions and differences
- [Typical developer workflow](https://github.com/phantomcyber/phantom-apps/blob/master/.github/DEV_WORKFLOW.md) - Configuring your dev environment
<!-- - [Testing Details](https://github.com/phantomcyber/phantom-apps/blob/next/.github/TESTING.md) - How we test apps & playbooks -->


## Step-by-Step Guide Available
If you are not familiar with a fork-and-branch Git workflow, or just feel a bit rusty on your Git knowledge, please check out our [step-by-step contribution guide](https://github.com/phantomcyber/phantom-apps/blob/next/.github/GUIDE.md) which has actual command line examples


# High Level Contribution Overview
## Contributing Bug-fixes
If you've found a bug and wish to fix it, the first thing to do is

1. [Fork](https://guides.github.com/activities/forking/) the project
1. Create a branch
1. Make your changes on your branch
1. Thoroughly test your changes. See the [Automated Checks](#automated-checks) section for information about basic automated checks we provide for all apps.
1. Add your name to the contributors list in the app JSON! [Example](https://github.com/phantomcyber/phantom-apps/pull/488/commits/a02e345ce48e56bcb8711d1c5c4e40dd6e62fd11?diff=split&w=1)
1. Open a [pull request](https://help.github.com/articles/using-pull-requests/) to the [next](https://github.com/phantomcyber/phantom-apps/tree/next) branch that gives edit access to the maintainers of the phantom-apps repo.

*****Important Notes:**

1. **Please make sure to check the 'Allow edits and access to secrets by maintainers' box during your PR submission so that a Splunk>Phantom developer can aid in the PR process.**

1. **Any pull-request to [Master](https://github.com/phantomcyber/phantom-apps/tree/master) will not be accepted**

1. **A Splunk>Phantom developer may wish to create a new branch and ask you to perform your pull-request there for specific types of changes.**

1. **One issue per branch. We will not accept any Pull Requests that affect more than one App or addresses more than one Issue at a time (unless the issue is a duplicate - discretion of our development team).**

## Contributing New Apps

If you've created a brand new App and wish to contribute it, the steps to do so are as follows.

1. [Fork](https://guides.github.com/activities/forking/) the project
1. Create a branch (following our [Conventions](https://github.com/phantomcyber/phantom-apps/blob/next/.github/CONVENTIONS.md)))
1. Create a new directory/folder for your App (again following the [Conventions](https://github.com/phantomcyber/phantom-apps/blob/next/.github/CONVENTIONS.md)).
1. Add your app code to the folder. Ensure no other folders are affected.
1. **Thoroughly** test your code for the new App. See the [Automated Checks](#automated-checks) section for information about basic automated checks we provide for all apps.
    <!-- 1. Ensure your new app has a [TESTING](https://about:blank) document for the community and our developers. -->
1. Add your name to the contributors list in the app JSON! [Example](https://github.com/phantomcyber/phantom-apps/pull/488/commits/a02e345ce48e56bcb8711d1c5c4e40dd6e62fd11?diff=split&w=1)
1. Perform a [pull request](https://help.github.com/articles/using-pull-requests/) to the [Next](https://github.com/phantomcyber/phantom-apps/tree/next) branch.

**Note: Any pull-request to [Master](https://github.com/phantomcyber/phantom-apps/tree/master) will not be accepted**

**Note: A Splunk>Phantom developer may wish to create a new branch and ask you to perform your pull-request there for specific types of changes.**

## Automated Checks
By default we provide various automated checks you can leverage to test your changes automatically. These checks will be run whenever you push new commits to your pull request branch. The overall pass/fail result will appear as a green checkmark or red "x" to the right of commit in the pull request page. To view the detailed report you can do **ANY** of the following:

- Click the checkmark or "x" and then click the "Details" link. **OR**
- Click the "Checks" tab at the top of the pull request. **OR**
- Click the "Details" link next to the list of checks that shows up at the bottom of the pull request. If the tests passed, this list will be hidden, so you will first need to click the "Show all checks" link.

After doing any of the above, the results will be under the "Test pull request" section in the log that shows up. If the overall result was a failure this section will automatically be open and scrolled to the bottom of the report. Otherwise, clicking on "Test pull request" will open up the report.

Alternatively, you can manually trigger the tests on-demand as described in the next section.

### How to Manually Run
Submit a new comment on the pull request starting with the text: **!scan**

If the command was processed, an _eyes_ reaction emoji will be added by the _github-actions_ bot. Then, the _phantom-apps-bot_ will post a Google Drive link to the results once they are ready.

There is a 10s rate limit for the scan command per pull request. If extra requests are sent during the rate limit window, the command will be processed (eyes emoji reaction) but there will be no results posted.

### Tests
The following are the current set of automated tests we run.

#### Compile Tests
* App compiles successfully for various Phantom versions.
#### Check Num of Apps Changed
* Only one app was changed.
* App directory contains only lowercase letters and/or numbers.
#### Min Phantom Version Test
* A valid minimum phantom version is specified in the app JSON.
* The minimum phantom version is greater than or equal to a certain version. The expected minimum version is maintained as a constant in the test script and will be updated as needed in the future.
#### License Usage
* `license` is specified in the app JSON.
* The license is a third-party license rather than copyrighted to Splunk if it is an external contribution.
#### Publisher
* `publisher` is specified in the app JSON.
* The publisher is either a third party or "Splunk Community", not "Splunk", if it is an external contribution.
#### Verify Password Config
* Fields in the app JSON that look like passwords, keys, tokens, etc. are marked with the `password` data type.
* `password` data type files in the app JSON should not have `default` or `value_list` fields specified.
#### Description Periods
* App and action descriptions in the app JSON do not end in periods.
#### Verbose Periods
* Verbose descriptions in the app JSON end in periods.
#### Action Names
* `product_vendor` and `product_name` fields are specified in the app JSON.
* Action names do not contain the product vendor or name.
#### Sequential Ordering
* Order is sequential and zero-indexed for:
  * App configuration parameters
  * Action parameters
  * Action output columns
#### Data Path Wildcards
* Checks that no data path contains sequential wildcards (`*.*`) since those result in incorrect reporting of result set sizes from the Phantom API.
#### Check Grammar
* First letter of all description and verbose fields is capitalized
#### README File
* If a README file exists, it is not empty.
#### Consts File
* If a consts file exists, it is not empty.
#### Optional Parameters
* Optional parameters are accessed with `.get()` instead of `[]`.

## Legal Notice

By submitting a Contribution to this Work, You agree that Your Contribution is made subject to the primary license in the Apache 2.0 license (https://www.apache.org/licenses/LICENSE-2.0.txt). In addition, You represent that: (i) You are the copyright owner of the Contribution or (ii) You have the requisite rights to make the Contribution.

### Definitions:

“You” shall mean: (i) yourself if you are making a Contribution on your own behalf; or (ii) your company, if you are making a Contribution on behalf of your company. If you are making a Contribution on behalf of your company, you represent that you have the requisite authority to do so.

"Contribution" shall mean any original work of authorship, including any modifications or additions to an existing work, that is intentionally submitted by You for inclusion in, or documentation of, this project/repository. For the purposes of this definition, "submitted" means any form of electronic, verbal, or written communication submitted for inclusion in this project/repository, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the maintainers of the project/repository.

“Work” shall mean the collective software, content, and documentation in this project/repository.
