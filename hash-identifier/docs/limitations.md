# Limitations of Structural Hash Identification

This document explains when the rule-based identifier cannot reliably tell which algorithm produced a string.

## Why this is a hard problem

The tool does not inspect the password, the original file, or the system that created the hash. It only looks at the shape of the string:

- known prefixes such as `$2b$` or `$argon2id$`
- length
- character set
- a few special formats such as JWTs or URLs

That means some strings are structurally ambiguous. The tool can suggest a likely answer, but it cannot always prove the exact algorithm.

## Cases that are ambiguous

### 1. MD5 vs NTLM

A 32-character hex string can be MD5, NTLM, MD4, or RIPEMD-128.

Why this is ambiguous:
- all of them share the same basic shape
- the input alone does not reveal which algorithm created it
- the tool must choose a likely guess, not a guaranteed answer

### 2. Truncated hashes

A truncated SHA-256 hash can look like a shorter hash such as MD5.

Why this is ambiguous:
- the string is shortened
- the remaining characters still look hash-like
- structure alone cannot tell whether the input was truncated or intentionally created as a shorter hash

### 3. Case and formatting variants

Some tools print the same hash in different cases or with different formatting.

Why this is ambiguous:
- uppercase and lowercase hex are both common
- some outputs may include prefixes, delimiters, or padding
- the same underlying data can appear in slightly different forms

### 4. PHC-style formats with overlapping structure

Modern password-hashing formats often use PHC-style strings, but different implementations may use similar-looking prefixes or payloads.

Why this is ambiguous:
- the structure can look correct without proving the exact algorithm
- some variants are not covered by explicit rules
- the tool may fall back to a generic PHC explanation

### 5. Encoded data that is not a hash

Strings that are base64, base32, or base58 can look hash-like even when they are not hashes at all.

Why this is ambiguous:
- these formats use character sets that resemble hash output
- the tool can recognize the shape but not the intended meaning
- a token, identifier, or encoded blob may be mistaken for a hash-like string

### 6. Human-chosen strings that accidentally fit a pattern

A short random-looking string can accidentally match a length rule or charset rule.

Why this is ambiguous:
- the tool only sees the string, not the context
- many non-hash strings can share a similar shape
- the resulting guess should be treated as a hint, not a fact

### 7. Composite lines and mixed data

A line such as `user:hash:salt` or `alice:$2b$...` mixes multiple fields in one string.

Why this is ambiguous:
- the tool may not know which field is the hash
- it cannot always tell whether the input is a single hash or multiple values in one line
- splitting and classification requires extra logic beyond pure shape matching

## What the tool should do instead

When the input is ambiguous, the tool should:

- return multiple candidates when appropriate
- rank them by likelihood
- use low confidence for shape-only matches
- be honest about uncertainty instead of pretending the answer is certain

## Tests added for this challenge

Three tests were added to make these limitations concrete in the repository:

- `test_md5_and_ntlm_are_indistinguishable_by_structure` shows that a 32-character hex string can still be treated as an MD5-style candidate even though NTLM is also a plausible match.
- `test_truncated_sha256_is_not_unambiguously_distinguished` shows that a truncated hash can still look like a shorter hash and cannot be proven from structure alone.
- `test_base64_blob_is_low_confidence_not_a_hash` shows that base64-looking data should be recognized as a non-hash shape hint rather than a confident hash guess.

## Practical takeaway

This tool is best used as a first-pass identifier. It is useful for narrowing the field, but it cannot always distinguish between similar formats without more context.
