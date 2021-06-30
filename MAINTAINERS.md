# Maintaining Notes

Releases are automatically drafted by [release-drafter](https://github.com/release-drafter/release-drafter), the next version number is automatically computed by the labels of PRs in the release.

See also .github/release-drafter.yml, if this label is in any PR, then the version change is marked that type of version change:

 - major release (+1.0.0): breaking-change, major
 - minor release (+0.1.0): minor, new-feature
 - patch (+0.0.1): this is the default release type

Before creating a release: Check the latest commit passes continuous integration.

When the release button on the draft is clicked, GitHub Actions will publish the release to PyPi.

After any push to the main branch, the "protoc-update" workflow is run which updates the generated python protobuf files. This is to ensure that if a contributor has a newer protoc version installed than the protobuf python package, we won't run into any issues.

