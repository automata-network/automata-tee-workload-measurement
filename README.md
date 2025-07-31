# Automata TEE Workload Measurement

This repo contains the onchain program (smart contracts) for verifying the integrity and measurement of a Confidential VM (CVM) workload hosted on cloud service providers.

Code and data in CVMs are protected from tampering by the host OS (and other CVMs) with TEE hardware, such as Intel TDX and AMD SEV-SNP. Cloud service providers generally also equip CVMs with virtual TPM, to cryptographically store measurements of the boot process, ensuring integrity of the CVM image.

Currently, the Workload verifier contract supports users who provisioned their CVMs equiped with Intel TDX or AMD-SEV-SNP, running on either Azure or Google Cloud Platform (GCP). The full workflow has been implemented in Solidity for EVM network. Click [here](./contracts/README.md) to learn more.

Ideally, the goal of this project is to be platform agnostic, covering as wide range of users as possible. We strive to continue to work diligently to support more TEEs, cloud providers and Web3 ecosystems.

## Deployment Info

TBD

## Licensing

This project is currently licensed under [Apache](./LICENSE).

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For questions and support, please open an issue.