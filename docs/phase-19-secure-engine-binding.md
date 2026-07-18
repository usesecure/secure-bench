# Phase 19 immutable Secure Engine binding

Secure Bench Phase 19 uses one explicit public Secure Engine release identity. It is not a request to resolve whichever release happens to be newest at execution time.

- Release: `https://github.com/usesecure/secure-engine/releases/tag/v0.1.6`
- Annotated tag: `v0.1.6`
- Signed tag object: `542d10b70987e6b5fe81af9d9f4a534703f18f25`
- Peeled release commit: `a921b9b0b737fa04af66903eeff43c1fd9ce6bcf`
- RPM: `secure-engine-0.1.6-1.fc44.x86_64.rpm`
- RPM SHA-256: `0f336a262d1c1cac51a73c625a7398c392feb9f3ecad2aa81f62cbc128a62a64`
- RPM-extracted `/usr/bin/secure` SHA-256: `ad91499f3de9918963c9189bd236f5eb99b78cb99954e30f50bbc3098f18a5e0`

The artifact is admitted only from the exact versioned GitHub release asset URL. A future release, moving selector, locally rebuilt executable, modified RPM, or modified extracted binary is a different artifact and is ineligible for Phase 19.

Binding verification consists only of schema validation, exact-value comparison, and SHA-256 over supplied bytes. It never installs the RPM, invokes the scanner, or rebuilds Secure Engine.
