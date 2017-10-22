[![Build Status](https://travis-ci.org/crypto-universe/SPECK.svg?branch=master)](https://travis-ci.org/crypto-universe/SPECK)
[![Clippy Linting Result](https://clippy.bashy.io/github/crypto-universe/SPECK/master/badge.svg)](https://clippy.bashy.io/github/crypto-universe/SPECK/master/log)

# SPECK

SPECK is a fast block cypher algorithm, introduced by NSA.
This algorithm is reliable, because it doesn't contain any initial constants.

This is an implementation in Rust.
SPECK implementation itself is stable, but CBC, paddings, etc. are NOT!

Also added ZUC encryption algorithm. For more details refer to
[Document1](https://www.gsma.com/aboutus/wp-content/uploads/2014/12/EEA3_EIA3_specification_v1_7.pdf),
[Document2](https://www.gsma.com/aboutus/wp-content/uploads/2014/12/eea3eia3zucv16.pdf),
[Document3](https://www.gsma.com/aboutus/wp-content/uploads/2014/12/eea3eia3testdatav11.pdf)
