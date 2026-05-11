# Changelog

All notable changes to sesam will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]


### Features
- Add mdbook docs template (4adeb5b)
- Add sketch for user manager (06b4a65)
- Make audit log use JSONL & make it crash safe (9715527)
- Add linter with somewhat okay default config and add to taskfile (a9fb39f)
- Add integrity check and split main into init/regular setup (9ab3dcc)
- Derive operation type from detail type in NewAuditEntry (5e7a5ac)
- Verify RootHash from latest seal against .sig.json files on disk (b861e13)
- Add generic secrets manager and bring it together with verify and audit log (1a1d200)
- Complete sketch of verification (59ce35a)
- Add rough implementation of a keyring (805d9a4)
- Mention `sesam apply` (6049b85)
- Make sure root hash is calculated from .sig files (e67103b)
- Cleanup public key handling and implement a proper whoami method (febe0d1)
- Rough sketch of how the audit log will work (f63282c)
- Make it possible to compare public keys (needed for mapping identity to recipient) (1bcf1d0)
- Lame attempt to make that generic (496bef5)
- Sketch out a way to implement an audit log (1375d5a)
- Make use of multicodec for self-describing hashes (1331d41)
- Add support for signature verify and signing (7ae0317)
- Some very basic proof of concept that can encrypt/decrypt a single file using a github name (051f2e9)
- Add some basic design doc, an example config file and a fist draft of a schema for the config (4b4803c)


### Bug Fixes
- Repair some medium security issues found with /security-review (b15003f)
- Repair some medium security issues found with /security-review (5319478)
- Various smaller fixes and cleanups (08e3804)
- Bad type assert (bb11551)
- Verify secret access based on existing groups not new ones (oops) (0c16c9b)
- Correct error messages in verify.go (1387467)
- Trust anchor needs to be in init entry (7888e34)
- Bye bitbucket, welcome codeberg (40f13fc)
- Wrong path for download cache (58230ea)


### Documentation
- Tiny add to whatis.md (8f2c446)
- Try faster mdbook-git download (c86e685)
- Bring back theme switch (4f31d99)
- Make sidebar more readable (55ddc0d)
- Add logo (76a8a67)
- Write some basic structure (3f26ffb)
- Theme it (e0446ae)
- Sync DESIGN.md with current code (22b9a44)
- Update DetailUserTell comment to reflect init-based bootstrap (f2ef2cb)


### Tests
- Make claude add a basic test suite (c14949c)


### Internal
- Add back prefix (2cce566)
- Conjure some alternative list out of thin air (rough overview for us, not for externals) (23e7388)
- Fix version (7b982df)
- Use pre-build mdbook (947b307)
- Cache mdbook (10d62a7)
- Remove not-yet-existing docgen on main (64031db)
- Fix doc generation (69cd9b6)
- Merge with audit branch (915c51d)
- Forgotten line (9ecb718)
- Signkey -> signkeys (e641996)
- RepoDir -> sesamDir (515e12a)
- Add some ideas for the readme (ee0e71a)
- Add CLAUDE.md (the parts that should be useful for everyone) (dd32f70)
- Move the init of the initial admin user to user_manager.go as well (b999f14)
- Smooth out secrets manager API a bit (e6bcc66)
- Shutup linter (3b24273)
- Just some more detailed error message (d575de6)
- One less depdency for secret manager (168122b)
- Remove some smaller outstanding TODOs (9061b1f)
- Part 1 (3d0b039)
- Fix a few annoying things (8a79d55)
- Clean up code a bit (a9b49c1)
- Some more fmt.Errorf (6a590c8)
- Add coverage (c365f56)
- Remove a bunch of outdated TODOs. (cd5a05c)
- Slightly refacor integrity.go (4e8661b)
- Remove outdated dependency on keyring in audit log (5c2358f)
- Make claude add a rough diagram (6aa43a8)
- Make AddOrChangeSecret() API easier (d1889ef)
- Make calling Update a bit easier (d819a13)
- Remove outdated section (015a666)
- Update design spec (6402d53)
- Review fixes (ac64230)
- Some more todos (5fe33d2)
- Add pr ttemplate (716029b)
- Cleanup a bit (83807cb)
- Some refinement of ideas, especially tempalting (940d7dc)


### Other
- Add log entry for adding initial user (59c89d9)
- Remove .claude dir (abc4034)
- Add logo (ca9b835)
- Add readme (8b4faf7)
- Initial commit (1eec7fc)


