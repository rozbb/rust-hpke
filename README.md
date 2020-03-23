# rust-hpke

This is an work-in-progress implementation of the [HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) hybrid encryption standard. Once this is passing known-answer tests, I'll publish it as a crate.

# What it implements

Currently, all of draft02 functionality is implemented, besides the single-shot API. In addition, the exporter API is implemented.

Not many algorithms are currently supported. Here's what we have:

* KEMs
    * DHKEM(Curve25519)
* KDFs
    * HKDF-SHA256
* AEADs
    * AES-GCM-128
    * AES-GCM-256
    * ChaCha20Poly1305

**THIS IMPLEMENTATION IS NOT KNOWN TO COMPLY WITH ANY STANDARDS...YET**

# What's next

1. Get known-answer tests working
2. Add support for more KEMs and KDFs
