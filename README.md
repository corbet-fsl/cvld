# cvld

Passkey authentication and privacy-preserving eligibility proofs with configurable independent phone, payment and voucher providers.

Experimental implementation using existing AnonCreds and WebAuthn libraries. Real cryptographic tests run in public CI with synthetic external-provider attestations. No compatible live provider has been integrated, and the complete deployment privacy claim is not established.

- [Behavioral contract](docs/contract.md)
- [Implementation and test evidence](studies/implementation-status.md)
- [Independent provider candidates](studies/independent-providers.md)
- [Studies](studies/README.md)
- [Experiments](experiments/README.md)

Run the documented tests on a supported development runner. Client/mobile portability, account lifecycle and durable storage are being tested separately; consult the implementation study for current limitations. The package is not yet published.

License: [FSL-1.1-ALv2](LICENSE.md). Third-party libraries retain their own licenses.
