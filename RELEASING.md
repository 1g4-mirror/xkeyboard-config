# How to make a xkeyboard-config release

### Prerequisites

- Have write access to xkeyboard-config Git repositories.

### Steps

#### Prepare the translations

**2 weeks before release:**

- [ ] Create a release branch: `git checkout -b release/MAJOR.PREV_MINOR.99 master`
  where `MAJOR.PREV_MINOR` is the *last* released version.

- [ ] Bump the `version` in `meson.build` to `MAJOR.PREV_MINOR.99`.

- [ ] Run `meson setup buildddir; ninja -C builddir dist` to make sure the release is good to go.

- [ ] Run `meson compile xkeyboard-config-pot` in builddir to update xkeyboard-config.pot file in po subdirectory.

- [ ] Commit `meson.build` and `po/xkeyboard-config.pot` to the branch.

- [ ] Merge the branch `release/MAJOR.PREV_MINOR.99` to `master` on gitlab.

- [ ] Send `po/xkeyboard-config.pot` and `builddir/meson-dist/xkeyboard-config-MAJOR.PREV_MINOR.tar.xz` to Translation Project asking for translations update: <coordinator@translationproject.org>

- [ ] Give the Translation Project *2 weeks* to update translations.

#### Prepare the release

- [ ] Ensure there is no issue in the tracker blocking the release. Make sure
  they have their milestone set to the relevant release and the relevant tag
  “critical”.

- [ ] Ensure all items in the current milestone are processed. Remaining items
  must be *explicitly* postponed by changing their milestone.

- [ ] Create a release branch: `git checkout -b release/MAJOR.MINOR master`.

- [ ] Bump the `version` in `meson.build`.

- [ ] Pull the latest translations from Translation Project by executing `scripts/pull_translations.sh`.

- [ ] Run `meson setup buildddir; ninja -C builddir dist` to make sure the release is good to go.

- [ ] Commit `git commit -m 'New version MAJOR.MINOR'`.

- [ ] Create a pull request using this template and ensure *all* CI is green.

- [ ] Merge the pull request.

- [ ] Tag `git switch master && git pull && git tag --annotate -m xkeyboard-config-<MAJOR.MINOR> xkeyboard-config-<MAJOR.MINOR>`.

- [ ] Push the tag `git push origin xkeyboard-config-<MAJOR.MINOR>`.

#### Send announcement email to xorg-announce

- [ ] Send an email to the xorg-announce@lists.x.org mailing list, using this template:

```
Subject: [ANNOUNCE] xkeyboard-config MAJOR.MINOR

<NEWS & comments for this release>

Git tag:
--------

git tag: xkeyboard-config-<MAJOR.MINOR>
git commit: <git commit sha>

<YOUR NAME>
```
