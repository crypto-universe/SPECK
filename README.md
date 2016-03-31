[![Build Status](https://travis-ci.org/crypto-universe/SPECK.svg?branch=master)](https://travis-ci.org/crypto-universe/SPECK)
[![Clippy Linting Result](https://clippy.bashy.io/github/crypto-universe/SPECK/master/badge.svg)](https://clippy.bashy.io/github/crypto-universe/SPECK/master/log)

# SPECK
SPECK is a fast block cypher algorithm, introduced by NSA.
This algorithm is reliable, because it doesn't contain any initial constants.

This is an implementation in Rust.
SPECK implementation itself is stable, but CBC, paddings, etc. are NOT!
