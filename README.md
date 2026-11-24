# WP9 test feeds (not for users)

Signed with a throwaway **test root**. Release builds of AtlasSOC never trust these files; only a `test-feed` build does, when it is given the root in `ROOT.txt`.

`EXPECTED.txt` lists the outcome of every variant for each channel. Each one was verified with `update_check::check` when the feeds were generated.

Generated with `cargo run -p threat-atlas-core --example make_test_feeds -- feed.json <out>` (branch `codex/claude-wp9-test-feeds`).
