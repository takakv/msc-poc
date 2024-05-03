# ZKRPs of ballot correctness

This is a proof of concept in Go which demonstrates the use of zero-knowledge range proofs to prove the encryption of a
message within an integer range.
In turn, this can be used in elections to prove that an encrypted ballot is for a valid candidate, without leaking who
the vote is for.

> Note: as this is a proof of concept, it should under no circumstances be used as-is in a production system! The code
> lacks testing, error handling, and is not side-channel safe on the client side (no sensitive data on the server side).

For black box use of the proofs:

- `voter.go` simulates a voter, who encrypts their choice and generates the ZKRPs
- `server.go` simulates the vote collector, who receives an encrypted vote and the ZKRPs and must verify their validity

For implementation details:

- `voteproof/` contains the implementation of the custom protocol for proving and verifying ballot correctness
- `bulletproofs/` contains the modified implementation of ING Bank's Bulletproofs

This code makes use of the [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) range
proof [implementation](https://pkg.go.dev/github.com/ing-bank/zkrp) by ING Bank which is modified to work with an
abstract interface for algebraic groups.
The interface is inspired by that of [CIRCL](https://github.com/cloudflare/circl), and is currently instantiated with
NIST's P-256 and P-384 curves.
