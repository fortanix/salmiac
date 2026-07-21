# Salmiac Beta Release Notes

## Overview

Beta advances salmiac from support for AWS Nitro Enclaves towards a common multi platform for VM based confidential computing enclaves.

## 22-07-2026

### TDX Converter Release version `0.46.3065`
Commit: `4b8e6b6`

#### New Features
- Added Intel TDX support for Salmiac. This includes container conversion, launch measurement generation and attestation client integration.
- Added GPU passthrough support for Intel TDX workloads.

#### Improvements
- Fixed the ability to use packaged base image tar archives when pre-requisite images are not available.

#### Limitations
- Application certificate and key are only available at default locations.
- Workflow config feature for TDX applications is available from CCM v4.12


## 12-06-2026

### SNP Converter Release version `0.45.2963`
Commit: `b2d8a6c`

### Improvements
- Maximum compressed image size limit for conversion is now configurable at build time.


## 05-06-2026

### SNP Converter Release version `0.44.2933`
Commit: `44710b3`

#### New Features
- Added support for building Salmiac enclaves for AMD SEV-SNP.
- Added support for GPU passthrough in SEV-SNP Salmiac enclaves.