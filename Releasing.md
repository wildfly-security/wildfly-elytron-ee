# Releasing Elytron EE

At this point in time the following branches are being maintained for the Elytron EE project:

 * 3.0.x (Requires Java 11)
 * 3.1.x (Requires Java 21)
 * 3.x (default): Jakarta EE 10 integration
 * 4.x: Jakarta EE 11 integration

With the exception of the `3.0.x` and `3.1.x` branches, all branches require **Java 25** to build and release.

To release Elytron EE first checkout the project and ensure you are on the latest commit for the branch you are releasing with no local changes.

Prior to releasing you should ensure you have your own GPG signing key set up, published to a key server and listed on [wildfly.org](https://www.wildfly.org/contributors/pgp/).

## Prepare the release

Execute:

    mvn release:prepare

Enter the version being released:

    What is the release version for "WildFly Elytron - Jakarta EE"? (elytron-ee) 3.2.1.CR1: 3.2.1.Final

The tag will default to the version:

    What is the SCM release tag or label for "WildFly Elytron - Jakarta EE"? (elytron-ee) 3.2.1.Final:

Set the next version:

    What is the new development version for "WildFly Elytron - Jakarta EE"? (elytron-ee) 3.2.2.Final-SNAPSHOT: 3.2.2.CR1-SNAPSHOT

The release commit can be checked with:

    git show ${TAG}

If everything is Ok perform the release which will deploy to Nexus.

## Perform the release

Execute:

    mvn release:perform

This will deploy the release to the `wildfly-staging` repository.

Wait for 10 minutes then visit the Validation task for the `wildfly-staging` repository in Nexus. If this task ran at least 10 minutes after the release was deployed check the latest results on the Settings tab and verify that at least one component was processed and that there were no errors. If the task has not run it can be manually kicked off using the Run button.

e.g.

> Processed 5 components.
> - no errors were found.
> - the deployment was a dry run (no actual publishing).

If others are also deploying at the same time this count could be higher, the important check is that the scan was at least 10 minutes after it was deployed, 1 or more components were scanned and no errors specific to Elytron EE are reported.

Nexus only scans components once if there are no issues so if you check these results after multiple scans the component count may be back to 0.

## Complete the release

If no issues are reported complete the release.

Move the component to the `wildfly-security` repository:

    git checkout ${TAG}
    mvn nxrm3:staging-move
    git checkout ${BRANCH}

Push the branch and tag to GitHub:

    git push upstream ${BRANCH}
    git push upstream ${TAG}

## Rollback the Release

If the release failed, revert the release.

Delete the component from Nexus:

    git checkout ${TAG}
    mvn nxrm3:staging-delete
    git checkout ${BRANCH}

Reset your local Git checkout:

    git reset --hard upstream/${BRANCH}
    git tag --delete ${TAG}

# Forward Merging

After releasing the 3.x branch, the changes must be merged to the 4.x branch to keep both branches synchronized.

The following example demonstrates merging from `3.x` to `4.x`:

    git checkout -b 4_x_sync -t upstream/4.x

Check the log from the 3.x branch and identify the last commit before the `[maven-release-plugin]` commits and merge it to this topic branch:

    git merge <COMMIT_SHA> -m "Sync from 3.x"

At this stage you may need to resolve any merge conflicts, be careful to not rebase - this should be committed as a merge commit.

Now we need to merge the release commits as well:

    git merge -s ours 3.x -m "Sync version commits from 3.x"

For this last command we use `-s ours` as we don't want git to actually apply these changes but we do want git to record that we have handled that part of merging.

This topic branch can now be submitted as a normal PR to kick off CI and merged once it passes. No review is required as this is merging previously approved changes unless you would like someone to verify especially if there were merge conflicts.

# CI Testing

The project uses GitHub Actions for continuous integration with comprehensive multi-version testing:

## Pull Request Testing
- Automatically runs on all pull requests
- Tests on Linux with Java 17, 21, and 25 (Temurin and Semeru distributions)
- 6 test permutations total

## Nightly Testing (LTS Versions)
- Scheduled daily at 2:00 AM UTC (3.x) and 2:30 AM UTC (4.x)
- Tests on Linux, Windows, and macOS
- Tests with Java 17, 21, and 25 (Temurin and Semeru distributions)
- 36 test permutations total (18 per branch)

## Non-LTS Testing
- Scheduled daily at 3:00 AM UTC (3.x) and 3:30 AM UTC (4.x)
- Tests on Linux with latest non-LTS Java version (currently 26)
- Tests with Temurin, Semeru, and Oracle distributions
- 6 test permutations total (3 per branch)

All workflows can be triggered manually via GitHub Actions UI for testing purposes.
