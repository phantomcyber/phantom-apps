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

- [Coding & Naming Conventions](https://github.com/phantomcyber/phantom-apps/blob/master/.github/CODING_CONVENTIONS.md) - How we expect to see code formatted and apps named
- [Certified vs Standard App](https://github.com/phantomcyber/phantom-apps/blob/master/.github/CERTIFIED_V_UNCERTIFIED.md) definitions and differences
- [Typical developer workflow](https://github.com/phantomcyber/phantom-apps/blob/master/.github/DEV_WORKFLOW.md) - Configuring your dev environment
- [Testing Details](https://github.com/phantomcyber/phantom-apps/blob/master/.github/TESTING.md) - How we test apps & playbooks


## Contributing Bug-fixes
If you've found a bug and wish to fix it, the first thing to do is 

1. If one does not already exist, create an Issue (otherwise we'll use the existing one)
1. [Fork](https://guides.github.com/activities/forking/) the project
1. Create a branch for the issue (following our [Naming Conventions](https://github.com/phantomcyber/phantom-apps/blob/master/.github/CODING_CONVENTIONS.md))
1. Make your changes on your branch
1. Thoroughly test your changes
1. Perform a [pull request](https://help.github.com/articles/using-pull-requests/) to the [next](https://github.com/phantomcyber/phantom-apps/tree/next) branch.

**Note: Any pull-request to [Master](https://github.com/phantomcyber/phantom-apps/tree/master) will not be accepted**

**Note: A Splunk>Phantom developer may wish to create a new branch and ask you to perform your pull-request there for specific types of changes.**

Remember:  One issue per branch. We will not accept any Pull Requests that affect more than one App or addresses more than one Issue at a time (unless the issue is a duplicate - discretion of our development team).

## Contributing New Apps

If you've created a brand new App and wish to contribute it, the steps to do so are as follows.

1. If one does not already exist, create an Issue (otherwise we'll use the existing one)
1. [Fork](https://guides.github.com/activities/forking/) the project
1. Create a branch for the issue (following our [Naming Conventions](https://(about:blank)))
1. Create a new directory/folder for your App, again following the [Naming Conventions](https://about:blank).
1. Add your app code to the folder. Ensure no other folders are affected.
1. **Thoroughly** test your code for the new App.
    1. Ensure your new app has a [TESTING](https://about:blank) document for the community and our developers.
1. Perform a [pull request](https://help.github.com/articles/using-pull-requests/) to the [Next](https://github.com/phantomcyber/phantom-apps/tree/next) branch. 

**Note: Any pull-request to [Master](https://github.com/phantomcyber/phantom-apps/tree/master) will not be accepted**

**Note: A Splunk>Phantom developer may wish to create a new branch and ask you to perform your pull-request there for specific types of changes.**
