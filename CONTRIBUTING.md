# Contributing guide

**Want to contribute? Great!**
We try to make it easy, and all contributions, even the smaller ones, are more than welcome. This includes bug reports, fixes, documentation, examples... But first, please take a moment to read this guide.

## Legal

### License

All original contributions to the Maven Assembly SBOM project are licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Developer Certificate of Origin (DCO)

All contributions are subject to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). The DCO
text is also included verbatim in the [dco.txt](dco.txt) file in the root directory of the repository.

Please sign off on your commits using `git commit -s`.

### Compliance with Laws and Regulations

All contributions must comply with applicable laws and regulations, including U.S. export control and sanctions restrictions.
For background, see the Linux Foundation's guidance:
[Navigating Global Regulations and Open Source: US OFAC Sanctions](https://www.linuxfoundation.org/blog/navigating-global-regulations-and-open-source-us-ofac-sanctions).

## Reporting an issue

This project uses [GitHub Issues](https://github.com/cyberstamp/maven-assembly-sbom/issues) to track bugs and feature requests.

If you believe you found a bug, please include:

- A clear description of what you are seeing and what you would expect to see.
- Steps to reproduce or a minimal reproducer project.
- Environment details: Java version, Maven version, versions of the artifacts from this project.

## Before you contribute

To contribute code or documentation, use GitHub Pull Requests from your **own** fork.

Make sure your Git authorship is set up correctly:

```sh
git config --global user.name "Your Full Name"
git config --global user.email your.email@example.com
```

We also recommend enabling rebase when pulling:

```sh
git config pull.rebase true
```

### Code reviews

All submissions need to be reviewed before being merged.
[GitHub Pull Request Review Process](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews) is followed for every pull request.

### Coding Guidelines

- **Atomic commits**: Commits should be atomic and semantic. Please properly squash fixup commits before submitting or when finalizing your pull request.
- **No `@author` tags**: We disallow `@author` tags in Javadoc and source code; authorship is tracked via Git history.
- **Tests**: Don't forget to include tests in your pull requests. Bug fixes and new features should be accompanied by automated tests.
- **Documentation**: If your change modifies user-facing behavior, configuration options, or adds a feature, keep the documentation up to date.

## Setup

### Prerequisites

- **Java**: JDK 17 or higher
- **Maven**: 3.9 or higher

### IDE Config and Code Style

This project enforces a consistent code style based on the Quarkus Eclipse formatter configuration:

- Code formatting is handled by `formatter-maven-plugin` (using `eclipse-format.xml` from `io.quarkus:quarkus-ide-config`) and `impsort-maven-plugin`.
- By default, running a build (such as `mvn compile` or `mvn test`) will format code and sort imports automatically.
- To run formatting without building:
  ```sh
  mvn process-sources
  ```
- To validate formatting without modifying sources (same check as CI):
  ```sh
  mvn verify -Dno-format
  ```

#### Eclipse Setup

1. Go to **Preferences** > **Java** > **Code Style** > **Formatter**. Click **Import** and select the `eclipse-format.xml` file from Quarkus (`quarkus-ide-config`).
2. Go to **Preferences** > **Java** > **Code Style** > **Organize Imports**. Click **Import** and select `eclipse.importorder`.

#### IDEA Setup

1. Install the [Adapter for Eclipse Code Formatter](https://plugins.jetbrains.com/plugin/6546-eclipse-code-formatter) plugin from the Marketplace.
2. In **Settings** > **Adapter for Eclipse Code Formatter**, enable Eclipse code formatter with `eclipse-format.xml` and import order `eclipse.importorder`.
3. Disable wildcard imports: go to **Settings** > **Editor** > **Code Style** > **Java** > **Imports** and set *Class count to use import with '\*'* and *Names count to use static import with '\*'* to `999`.

Alternatively, you can rely on Maven to automatically format modified files on build or via `mvn process-sources`.

## Build

To build the project and run all tests:

```sh
mvn clean install
```

To run a single test class:

```sh
mvn test -Dtest=ArchiveAnalyzerTest
```

To verify the build and check formatting without reformatting:

```sh
mvn verify -Dno-format
```

## Continuous Integration

All pull requests and pushes to `main` are built with GitHub Actions using:

```sh
mvn -B verify -Dno-format
```

The CI build will fail if formatting or import sorting produces any changes. Always ensure `mvn verify -Dno-format` passes locally before submitting your pull request.

## The small print

This is an open source project. Please act responsibly, be nice and polite, and enjoy!
