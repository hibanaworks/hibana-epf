# hibana-epf

`hibana-epf` is the optional EPF appliance crate extracted from `hibana` core.

It owns:

- bytecode image headers and verification
- slot-scoped host installation and scratch leasing
- VM execution through `run_with(...)`

The crate's default manifest lane depends on an immutable `hibana` GitHub rev.
Coordinated local-worktree validation belongs to the dedicated
`hibana-cross-repo` workspace smoke runner, which applies explicit CLI patch
overlays for the sibling checkouts.
