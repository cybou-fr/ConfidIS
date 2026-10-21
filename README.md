<p align="center"><img src="web-ui/public/logo.svg" alt="CONFIDIS" width="120" height="120" /></p>

# ConfidIS OS

**🇫🇷 [Étude de cas — Architecture distribuée et stockage chiffré](docs/CASE_STUDY_FR.md)** — Modules Rust, choix de conception et limites.

**ConfidIS OS is an open-source, Debian-based appliance for creating temporary, encrypted personal data cells, trusted node federation, and operational audit evidence.**

*Documentation disponible en français dans [README_FR.md](README_FR.md).*

ConfidIS OS allows an organization to deploy its own storage node on its infrastructure: Proxmox, VM, mini-server, VPS, or bare metal. The project is a local-first, self-hosted software solution designed for sovereignty, data privacy, and compliance (GDPR, NIS2, ANSSI guidelines).

## Core Concepts

ConfidIS OS is not a general-purpose file cloud, a permanent backup system, or a public storage marketplace. It serves a specific purpose: enabling organizations to handle sensitive personal data without unnecessarily becoming the permanent holder of that data in plaintext.

*   **Temporary, Encrypted Data Cells:** Data is encrypted client-side with a key held solely by the owner, shredded using Reed-Solomon erasure coding, and distributed across independent storage nodes.
*   **Zero-Knowledge:** Nodes only store encrypted shards and BLAKE3 hashes. They have no access to plaintext, filenames, or decryption keys.
*   **Trusted Node Federation:** Federation is built on explicit agreements between trusted nodes. Each node configures its partners, endpoints, and mutual usage limits.
*   **Operational Evidence:** The system produces audit trails, signed receipts for storage and deletion, and readiness reports for compliance auditing.

---

## Compliance Alignment

ConfidIS OS is designed to support deployments aligned with **GDPR, NIS2, and ANSSI recommendations**:
- Privacy by design and by default.
- Client-side encryption.
- Enforced data retention limits.
- Trusted federation.
- Separation of user/operator surfaces.
- Exportable audit evidence packs.

*Note: The project does not claim ANSSI certification or specific regulatory qualification. Deployment-specific compliance audit and validation remain the responsibility of the organization.*

---

## Technical Model

ConfidIS OS operates without tokens, internal credits, crypto-economics, or public storage marketplaces. Usage is regulated through:
- Local node quotas.
- Service plans.
- Organizational policies.
- Explicit federation agreements.
- Signed usage receipts and audit logs.

---

## Getting Started

### Prerequisites
- Debian-based environment (Proxmox, VM, or bare metal).
- Administrative access for setup.

### Deployment Options
- **Proxmox:** Use the QCOW2 image.
- **Bare Metal:** Use the ISO image for dedicated servers.
- **Docker (Development/Demo):** Use the provided Docker configurations.
- **Debian:** Install using the provided Debian packaging scripts.

For detailed setup instructions, see the `deploy/` directory.

---

## Contributing

We welcome contributions to ConfidIS OS. Please refer to our contribution guidelines (to be added) for more information.

---

## Support & Donations

ConfidIS OS is an open-source project maintained by the community and supported by professional services. If you find value in this project, please consider supporting its development and long-term sustainability:

*   **Contribute Code:** Check out our open issues and submit pull requests.
*   **Report Issues:** Help us improve stability by reporting bugs.
*   **Sponsorship:** If you are an organization using ConfidIS OS, consider sponsoring our development or engaging our professional services (installation, training, support, audit assistance). 

For donation or sponsorship inquiries, please contact us at ioustamora@gmail.com. Your support helps keep ConfidIS OS secure, compliant, and free for everyone.

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
