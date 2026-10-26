# Demo manifests

Sample inputs for the manifest parser and the vulnerability analysis feature. The dependency versions in these files are old on purpose so that an assessment run against them has findings.

The Maven sample is not named pom.xml, because GitHub's dependency graph treats any pom.xml in the repository as a real build manifest and raises Dependabot alerts against it. Keep the sample under a name that no manifest parser recognizes.
