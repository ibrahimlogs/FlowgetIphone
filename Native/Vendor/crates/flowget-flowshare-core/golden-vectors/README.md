# FlowShare v3 golden vectors

`flowshare-v3.json` is language-neutral compatibility input for Desktop and Android. It freezes byte order, canonical candidate representation, capability and resume digests, transfer commitment, and checkpoint authentication. Android tests must consume this file unchanged; do not regenerate it during tests.

Run `cargo run --example generate_golden_vectors` only when reviewing an intentional protocol migration. Any output change while `wireProtocolVersion` remains `3` is a release blocker.
