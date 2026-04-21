WildFly Elytron - Jakarta EE
============================

[WildFly Elytron](https://wildfly-security.github.io/wildfly-elytron/) is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and server security mechanism.

This repository contains the Jakarta EE integration code for WildFly Elytron, providing integration with:
- Jakarta Authentication (JASPIC)
- Jakarta Authorization (JACC)
- Jakarta Security
- RESTEasy and Web Services clients

An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

```console
$ git clone git@github.com:wildfly-security/wildfly-elytron-ee.git
```

Setup the JBoss Maven Repository
--------------------------------

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see http://community.jboss.org/wiki/MavenGettingStarted-Users

Build with Maven
----------------

### Requirements

- **Java 25** or later (for building)
- **Maven 3.6.0** or later

The project builds with Java 25 and targets Java 17 bytecode for backwards compatibility.

### Basic Build

The command below builds the project and runs the embedded suite.

```console
$ mvn clean install
```

### Multi-Version Testing

This project supports testing against multiple Java versions (17, 21, and 25) using Maven Toolchains.

#### Setup Toolchains

1. Copy the toolchains template:
   ```console
   $ cp toolchains.xml.template ~/.m2/toolchains.xml
   ```

2. Edit `~/.m2/toolchains.xml` and update the `<jdkHome>` paths to match your JDK installations.

3. Verify your toolchains configuration:
   ```console
   $ mvn toolchains:display-toolchains
   ```

For automated JDK installation using SDKMAN!, see the comments in `toolchains.xml.template`.

#### Testing with Specific Java Versions

Test with a specific Java version:
```console
$ mvn clean test -Djdk.test.version=17
$ mvn clean test -Djdk.test.version=21
$ mvn clean test -Djdk.test.version=25
```

Test with a specific JDK vendor (Temurin or Semeru):
```console
$ mvn clean test -Djdk.test.version=21 -Djdk.test.vendor=semeru
```

#### Comprehensive Multi-Version Testing

Test against all supported Java versions (17, 21, 25) in sequence:
```console
$ mvn clean install -Ptest-all-versions
```

Test with Semeru distribution:
```console
$ mvn clean install -Ptest-all-versions -Djdk.test.vendor=semeru
```

This will create separate test report directories for each Java version:
- `target/surefire-reports-java17-temurin/`
- `target/surefire-reports-java21-temurin/`
- `target/surefire-reports-java25-temurin/`

Continuous Integration
---------------------

This project uses GitHub Actions for continuous integration with comprehensive multi-version testing:

### Pull Request Testing
- **Trigger**: Automatically on pull requests
- **Platform**: Linux only
- **Java Versions**: 17, 21, 25
- **JDK Distributions**: Temurin, Semeru
- **Total Permutations**: 6 (3 versions × 2 distributions)

### Nightly Testing (LTS Versions)
- **Trigger**: Scheduled daily at 2:00 AM UTC (3.x branch) and 2:30 AM UTC (4.x branch)
- **Platforms**: Linux, Windows, macOS
- **Java Versions**: 17, 21, 25
- **JDK Distributions**: Temurin, Semeru
- **Total Permutations**: 36 (18 per branch: 3 platforms × 3 versions × 2 distributions)

### Non-LTS Testing (Latest Java)
- **Trigger**: Scheduled daily at 3:00 AM UTC (3.x branch) and 3:30 AM UTC (4.x branch)
- **Platform**: Linux only
- **Java Version**: 26 (configurable)
- **JDK Distributions**: Temurin, Semeru, Oracle
- **Total Permutations**: 6 (3 per branch: 3 distributions)

All workflows can be triggered manually via GitHub Actions UI for testing purposes.

Issue Tracking
--------------

Bugs and features are tracked within the Elytron EE Jira project at https://issues.jboss.org/browse/ELYEE

Contributions
-------------

This project maintains two stable branches:
- **3.x** (default): Jakarta EE 10 integration
- **4.x**: Jakarta EE 11 integration

Changes to the 3.x branch are regularly merged to 4.x to keep both branches synchronized.

Our [contribution guide](https://github.com/wildfly-security/wildfly-elytron-ee/blob/3.x/CONTRIBUTING.md) will guide you through the steps for getting started on the WildFly Elytron EE project and will go through how to format and submit your first PR.

For more details about WildFly Elytron, check out the [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.
