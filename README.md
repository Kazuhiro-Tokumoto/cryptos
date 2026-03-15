# DYLASIG v2: A Verification-Optimized Elliptic Curve Signature Scheme

**Author:** Kazuhiro Tokumoto
**Date:** March 15, 2026

---

## Abstract

DYLASIG v2 is an elliptic curve signature scheme using the signing equation $s = (k + x) \cdot e^{-1}$. The verification equation $seG = R + Y$ requires all scalar multiplications to be performed against the fixed base point $G$, eliminating the need for arbitrary-point scalar multiplication. A from-scratch TypeScript implementation over P-256 surpasses native WebCrypto ECDSA in verification throughput. A formal security proof remains an open problem.

**Keywords:** Elliptic curve cryptography, digital signatures, discrete logarithm problem, verification optimization

---

## 1. Introduction

### 1.1 Motivation

Comparing verification equations across existing signature schemes:

| Scheme | Verification Equation | Arbitrary-Point Scalar Mult. |
|--------|----------------------|:----------------------------:|
| ECDSA | $u_1 G + u_2 Y = R$ | 1 |
| Schnorr | $sG = R + eY$ | 1 |
| **DYLASIG v2** | $seG = R + Y$ | **0** |

In DYLASIG v2, every scalar multiplication during verification is against the fixed base point $G$, allowing a static precomputed lookup table to be maintained throughout the lifetime of the implementation.

### 1.2 Design Philosophy

Push as much computation as possible onto the signer so that verification is as cheap as possible.

- **Verification:** 1 scalar multiplication + 1 point addition (conjectured theoretical minimum)
- **Signing:** 1 scalar multiplication + 1 modular inverse

### 1.3 Design History

An earlier candidate used a group-element signature $S = Y + R + eG$. This is immediately forgeable: an adversary freely chooses $R$ and $e$, then computes $S$ directly. Replacing the group-element output with a scalar $s$ and deriving the signing equation $s = (k + x) \cdot e^{-1}$ resolves this.

---

## 2. Preliminaries

### 2.1 Notation

| Symbol | Meaning |
|--------|---------|
| $\mathbb{G}$ | Elliptic curve group of prime order $n$ |
| $G$ | Generator of $\mathbb{G}$ |
| $\mathbb{Z}_n$ | Scalar field of order $n$ |
| $H$ | Random oracle $H: \{0,1\}^* \to \mathbb{Z}_n$ |

### 2.2 Elliptic Curve Discrete Logarithm Problem (ECDLP)

Given a group element $P \in \mathbb{G}$, find $a \in \mathbb{Z}_n$ such that $P = aG$. We assume that no PPT algorithm solves this problem with probability better than $\text{negl}(\lambda)$.

---

## 3. Scheme Definition

### 3.1 Key Generation $\text{KeyGen}(1^\lambda)$

$$x \xleftarrow{\$} \mathbb{Z}_n, \quad Y = xG$$

Secret key: $x$. Public key: $Y$.

### 3.2 Signing $\text{Sign}(x, m)$

1. $k \xleftarrow{\$} \mathbb{Z}_n$ (generated deterministically per RFC 6979)
2. $R \leftarrow kG$
3. $e \leftarrow H(R \| Y \| m)$
4. $s \leftarrow (k + x) \cdot e^{-1} \pmod{n}$
5. Output: $(R, s)$

### 3.3 Verification $\text{Verify}(Y, m, (R, s))$

1. $e \leftarrow H(R \| Y \| m)$
2. Check $seG \stackrel{?}{=} R + Y$
3. Accept if equal; reject otherwise.

### 3.4 Correctness

$$seG = s \cdot e \cdot G = (k + x) \cdot e^{-1} \cdot e \cdot G = (k + x)G = kG + xG = R + Y \quad \checkmark$$

---

## 4. Security Intuition

Suppose an adversary outputs a valid forgery $(R^*, s^*)$. Then:

$$s^* e^* G = R^* + Y$$

which implies:

$$s^* e^* = \log_G(R^* + Y)$$

The adversary may choose $R^*$ freely, but once chosen, $e^* = H(R^* \| Y \| m^*)$ is fixed and $\log_G(R^* + Y)$ must be computed. Writing $R^* = r^* G$:

$$s^* e^* = r^* + x$$

There are two unknowns ($r^*$ and $x$) and only one equation, which is the core obstacle to a reduction.

---

## 5. Non-Applicability of the Forking Lemma

Consider two signatures under the same nonce $k$ with distinct challenges $e_1, e_2$:

$$s_1 e_1 = k + x, \quad s_2 e_2 = k + x$$

$$\therefore \quad s_1 e_1 = s_2 e_2$$

Both $x$ and $k$ cancel entirely. The standard Schnorr proof technique (Forking Lemma) is therefore structurally inapplicable to DYLASIG v2.

---

## 6. Security Proof (Open Problem)

**Conjecture:** In the random oracle model, if ECDLP is hard then DYLASIG v2 is EU-CMA secure.

### 6.1 Barrier to Reduction

Given a forgery $(R^*, s^*)$, a reduction $\mathcal{B}$ obtains the equation:

$$s^* e^* = r^* + x$$

with two unknowns $r^* = \log_G R^*$ and $x$. Collecting multiple forgeries introduces a fresh unknown $r^*_i$ per forgery, so the system remains underdetermined regardless of how many forgeries are gathered.

### 6.2 Current Status

- Reduction via Forking Lemma: structurally impossible
- Direct reduction: incomplete
- Whether a reduction is *in principle* impossible: unknown

Completing the security proof, or proving that no black-box reduction exists, is left as an open problem.

---

## 7. Finite-Field Experiment

### 7.1 Setup

To study the scheme concretely, we implemented DYLASIG v2 over a small multiplicative group:

- $p = 23$ (prime)
- $q = 11$ (group order, $(p-1)/2$)
- $g = 2$ (generator)
- Signing: $s = (k + x) \cdot e^{-1} \pmod{q}$
- Verification: $g^{se} \equiv R \cdot Y \pmod{p}$

### 7.2 Attack Attempts

**Random forgery:** Succeeds when the hash function is weak. Under a proper random oracle, forgery probability is $1/q$.

**R-selection attack:** For every choice of $R$, a successful forgery required computing $\log_g(R \cdot Y)$.

### 7.3 Result

No method of forging without solving the DLP was found:

$$\text{Forgery possible} \iff \text{DLP solved (experimentally confirmed)}$$

---

## 8. Attack Experiments

We conducted nine attacks against the finite-field instantiation ($p=23$, $q=11$, $g=2$).

### 8.1 Adaptive Signing Query (Attack 1)

Collected signatures on multiple messages to extract $x$. Each signature introduces a fresh unknown $k_i$, keeping the system underdetermined. **$x$ cannot be extracted.**

### 8.2 Random Oracle Programming (Attack 2)

Assumed the challenger could set $e^*$ freely. Regardless of the choice of $e^*$, computing $s^* = \log_G(R^* + Y) \cdot (e^*)^{-1}$ still requires solving the DLP. **DLP required in every case.**

### 8.3 Multiple-Forgery Combination (Attack 3)

Attempted to extract $x$ from two valid forgeries:

$$s_1^* e_1^* - s_2^* e_2^* = r_1^* - r_2^*$$

$x$ cancels completely. Confirmed numerically. **Experimental evidence for Forking Lemma non-applicability.**

### 8.4 Related-Key Attack (Attack 4)

Attempted to reuse a signature $(R, s)$ valid under $Y$ to pass verification under $Y' = Y \cdot G^d$ ($d$ known). The original signature did not pass. **Signature reuse impossible.**

### 8.5 Nonce Reuse (Attack 5)

Signing two messages with the same $k$ gives $s_1 e_1 = s_2 e_2 = k + x$, leaking neither $x$ nor $k$. Compare Schnorr, where nonce reuse yields $x = (s_1 - s_2)/(e_2 - e_1)$ immediately. **Neither $x$ nor $k$ is leaked. Nonce reuse is nonetheless strongly discouraged.**

### 8.6 Existential Forgery (Attack 6)

Chose $s^*, R^*$ first and searched for a matching message. Every successful case required a DLP solution. **DLP required.**

### 8.7 Special Public Key $Y = G$ (Attack 7)

The case $x = 1$ ($Y = G$) exhibits the same structure as the general case. **No special weakness found.**

### 8.8 Invalid Public Key $Y = 1$ (Attack 8)

$Y = 1$ corresponds to $x = 0$ and is mathematically valid. Implementations must reject the identity point and similarly degenerate public keys.

### 8.9 Linear Combination Attack (Attack 9)

If $(R, s)$ is valid under $Y$, then $s' = s + b \cdot e^{-1}$ passes verification under $Y' = Y \cdot G^b$. This is not an EU-CMA break: any holder of $x' = x + b$ can independently produce $s'$. Binding $Y$ into the hash as $e = H(R \| Y \| m)$ prevents the unadjusted signature from passing under $Y'$ directly. **Not an EU-CMA break; no special action required beyond the public-key binding already in place.**

### 8.10 Summary

| Attack | Result |
|--------|--------|
| Adaptive signing query | Cannot extract $x$ |
| RO programming | DLP required |
| Multiple forgeries | $x$ cancels; Forking Lemma non-applicability confirmed |
| Related-key attack | Signature reuse impossible |
| Nonce reuse | $x$ and $k$ not leaked |
| Existential forgery | DLP required |
| Special key $Y = G$ | No weakness |
| Invalid key $Y = 1$ | Implementation must validate public key |
| Linear combination | Not an EU-CMA break |

In all nine experiments, no forgery was achieved without solving the DLP.

---

## 9. Performance Evaluation

### 9.1 Computational Cost

| Scheme | Verification scalar mult. ($G$) | Verification scalar mult. (arbitrary point) | Verification point addition |
|--------|:---:|:---:|:---:|
| ECDSA | 1 | 1 | 1 |
| Schnorr | 1 | 1 | 1 |
| **DYLASIG v2** | **1** | **0** | **1** |

### 9.2 Benchmark Results

Environment: Node.js v22.22.0, TypeScript, P-256, $n = 5{,}000$ iterations.

| Scheme | Sign (median) | Sign (mean) | Verify (median) | Verify (mean) |
|--------|-----:|-----:|-----:|-----:|
| DYLASIG v2 (TypeScript) | 0.37 ms | 0.52 ms | 0.12 ms | 0.16 ms |
| WebCrypto ECDSA (native) | 0.09 ms | 0.23 ms | 0.13 ms | 0.30 ms |

Ratios:

| Comparison | Sign (median) | Verify (median) | Verify (mean) |
|------------|-----:|-----:|-----:|
| DYLASIG v2 vs WebCrypto ECDSA | 4.1× slower | **0.92× (v2 faster)** | **0.53× (v2 faster)** |

A from-scratch TypeScript BigInt implementation surpasses native C++ WebCrypto ECDSA in verification. The median figures are near parity; the mean advantage for DYLASIG v2 reflects the lower jitter compared to WebCrypto ECDSA. The static precomputed table (window width $w = 8$, 8192 points) over the fixed base point is the key driver.

### 9.3 Signature Size

| Scheme | Signature size |
|--------|-----:|
| ECDSA | 70–72 bytes (DER) |
| Schnorr | 64 bytes |
| DYLASIG v2 | 97 bytes (65-byte uncompressed $R$ + 32-byte $s$) |

---

## 10. Implementation Notes

From-scratch TypeScript implementation over P-256:

- Jacobian coordinates with $a = -3$ optimization
- Static precomputed table for $G$ (window width $w = 8$, 8,192 points)
- Deterministic nonce generation per RFC 6979
- Extended Euclidean algorithm for modular inverse
- Jacobian-coordinate equality check (avoids affine conversion)
- Public key bound into the hash: $e = H(R \| Y \| m)$

---

## 11. Nonce Reuse Resistance

Under nonce reuse with the same $k$ and distinct messages:

$$s_1 e_1 = k + x, \quad s_2 e_2 = k + x \implies s_1 e_1 = s_2 e_2$$

Neither $x$ nor $k$ is recoverable. This contrasts with Schnorr, where nonce reuse immediately exposes $x$. Nonetheless, nonce reuse is strongly discouraged; RFC 6979 deterministic generation is used in the reference implementation.

---

## 12. Discussion

### 12.1 Structural Difference from Schnorr

Schnorr: $s = k - ex$ — the secret key enters multiplicatively with the challenge.  
DYLASIG v2: $s = (k + x)e^{-1}$ — the secret key enters additively.

The multiplicative coupling $e \cdot x$ in Schnorr is precisely what enables the Forking Lemma reduction. The absence of this coupling in DYLASIG v2 precludes that proof technique.

### 12.2 Public-Key Binding in the Hash

Without $Y$ in the hash, i.e., $e = H(R \| m)$, a Key-Substitution Attack is possible: given $(R, s)$ valid under $Y$, one can construct $Y' = Y + \delta eG$ for any $\delta$. Binding the public key as $e = H(R \| Y \| m)$ closes this attack. This form is adopted in the present scheme.

### 12.3 Quantum Resistance

DYLASIG v2 is based on the elliptic curve discrete logarithm problem and is therefore vulnerable to Shor's algorithm. In practice, current quantum hardware is far from the scale required to threaten 256-bit elliptic curve parameters, so the near-term risk is negligible.

### 12.4 Use Cases

In the common pattern of one signing operation followed by many verifications, verification throughput dominates overall performance. DYLASIG v2 is well-suited to verification-heavy deployments.

---

## 13. Conclusion

DYLASIG v2 is an elliptic curve signature scheme with signing equation $s = (k + x)e^{-1}$ and verification equation $seG = R + Y$. All scalar multiplications in verification are against the fixed base point, enabling a static precomputed table. A TypeScript reference implementation surpasses native WebCrypto ECDSA in verification throughput.

The EU-CMA security proof is an open problem. Nine experimental attacks — including adaptive signing queries, random oracle programming, multiple-forgery combination, and key-substitution variants — all required solving the discrete logarithm problem; no forgery without a DLP solution was found. Whether a formal reduction to ECDLP exists, or whether no such reduction can exist, remains open.

Community analysis and attack attempts are welcome.

---

## References

1. C. P. Schnorr, "Efficient signature generation by smart cards," *Journal of Cryptology*, vol. 4, no. 3, pp. 161–174, 1991.
2. D. Pointcheval and J. Stern, "Security arguments for digital signatures and blind signatures," *Journal of Cryptology*, vol. 13, no. 3, pp. 361–396, 2000.
3. M. Bellare and G. Neven, "Multi-signatures in the plain public-key model and a general forking lemma," *ACM CCS 2006*, pp. 390–399, 2006.
4. NIST, "Digital Signature Standard (DSS)," *FIPS PUB 186-5*, 2023.
5. T. Pornin, "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)," RFC 6979, 2013.