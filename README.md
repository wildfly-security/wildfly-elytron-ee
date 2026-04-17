WildFly Elytron
===============

[WildFly Elytron](https://wildfly-security.github.io/wildfly-elytron/) is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and  server security mechanism.
 
An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

```console
$ git clone git@github.com:wildfly-security/wildfly-elytron.git
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

Issue Tracking
--------------

Bugs and features are tracked within the Elytron Jira project at https://issues.jboss.org/browse/ELY

Contributions
-------------

All new features and enhancements should be submitted to 1.x branch only.
Our [contribution guide](https://github.com/wildfly-security/wildfly-elytron/blob/1.x/CONTRIBUTING.md) will guide you through the steps for getting started on the WildFly Elytron project and will go through how to format and submit your first PR.
 
For more details, check out our [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.
