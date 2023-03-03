# Publishing to our npm registry

Package is published automatically via github action on each push to master.

NOTE: publishing will fail if given version has already been published so we should not merge to master without bumping version in package.json.

Also, remember to make sure that any new files, which need to be included in the package, are covered by "files" list in `package.json`.

## Publishing manually

From nix shell:

```sh
npm-publish
```
