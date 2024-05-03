# ZKPs of ballot correctness

This is a proof of concept in Go which demonstrates the use of zero-knowledge range proofs to prove the encryption of a
message in an integer range.

This code makes use of the [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) range
proof [implementation](https://pkg.go.dev/github.com/ing-bank/zkrp) by ING Bank which is modified to work with an
abstract interface for algebraic groups.
The interface is inspired by that of [CIRCL](https://github.com/cloudflare/circl), and is currently instantiated with
NIST's P-256 and P-384 curves.