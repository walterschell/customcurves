# Description
customcurves contains experimental alternate elliptic curve implementations.

**THEY ARE NOT CRYPTOGRAPHICALLY SAFE**

In particular they use naive addition and multipication algorithms that will leak timing details.

## smallcurve
smallcurve is optimized for use on curves where all of the math is on numbers 64 bits or less

## weierstrass
weierstrass is for manipulating prime order weierstrass curves (e.g. P-256)
Uses complete addition formula from https://eprint.iacr.org/2015/1060.pdf, but naive double and add for multipication

## weierstrass/schnorr
schnorr is for generating and validating schnorr signatures


# Schnorr Signatures

Short Schnorr Signatures are considered "short because they use a truncated hash for their parameters
and only requre `3*N` bits to represent a signature with `N` bit security instead of `4*N` used by other schemes.
For a well chosen prime order curve, `N` is equal to half of the bitlength of prime over which the curve field is defined

## Parameters
Domain Parameters
------------------
- `p`    - prime defining field
- `H(x)` - TrucatedSha256(X) (bitlen(`p`)/2 bits)
- `G`    - generator (Point)

User Parameters:
----------------
- `k`    - signing secret key (scalar)
- `P`    - signing public key (point)

Per Signature Parameters:
-------------------------
- `M`    - message (bytes)
- `r`    - ephemeral signing scalar (never transmitted, or re-used)
- `R`    - ephemeral signing point corrisponding to r (recovered during verification)  
  `R = G * r`

Signature
-------------------------
- `e`    - challenge (scalar) (bitlen(`p`)/2 bits)
- `s`    - proof (scalar) (bitlen(`p`) bits)


### Algorithm
Sign Phase
----------
1. Construct challenge and bind it to message, public key and ephemeral public key  
   `e = H(R || P || M)`

2. Construct proof that signer knows k  
   `s = r + ke`

Verify Phase
------------
1. Recover `R (G * r)` from `s`,`e`,`P`,`G`           
   `R = (G * s) - (P * e)`  
   [Proof that `R = G*r = G*s - P*e` ](#proof)


2. Compute `e'` from `R`, `P`, `M`  
   `e' = H(R || P || M)`

3. Verify `e = e'`


### Proof
| Step                                 |Explanation                                   |
|:-------------------------------------|:-----------|
| `s = r +ke`                          | Definition of `s` |
| `R = G * r`                          |  Definition of `R`   |
| `R = G * (r + ke - ke)`              |  Add and subtract `ke` |  
| `R = (G * (r + ke)) - (G * ke)`      | Distribute `G` |
| `R = (G * (r + ke)) - ((G * k) * e)` | Extract `e` |
| `R = (G * s) - (P * e)`              | Substitute `s` for `(r + ke)` and `P` for `(G * k)` |
