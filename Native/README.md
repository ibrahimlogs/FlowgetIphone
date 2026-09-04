# FlowShare native core

`Vendor/crates/flowget-flowshare-core` is an exact source snapshot of the proprietary
FlowGet repository at the full revision recorded in `flowshare-core.source`. It is the
same authoritative protocol-v3 Rust/UniFFI core consumed by FlowGet Android; this iOS
project does not implement a second transfer protocol.

The source commit is not currently advertised by the shared repository's GitHub
remote, so the snapshot is intentionally included here to make a fresh iOS clone
buildable. `build-flowshare-core.sh` applies the reviewed Cargo lock, produces device
and simulator static libraries, verifies the checked-in generated Swift ABI, and
packages `FlowGetNativeCore.xcframework` locally. Build products are not committed.
