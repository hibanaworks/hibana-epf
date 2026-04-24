# hibana-epf

`hibana-epf` is the optional EPF appliance crate extracted from `hibana` core.

It owns:

- bytecode image headers and verification
- slot-scoped host installation and scratch leasing
- VM execution through `run_with(...)`

The crate depends on the sibling `hibana` checkout through an explicit local
path dependency. Coordinated development runs against the current worktree with
no extra git-rev lane and no repo-local patch shim.
