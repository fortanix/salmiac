#!/usr/bin/env python3
#
# Copyright (c) Fortanix, Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import sys
from pathlib import Path

from sevsnpmeasure.guest import calc_launch_digest
from sevsnpmeasure.sev_mode import SevMode

FORTANIX_VME_VCPU_SIG = 0
# TODO: needs security hardening.
FORTANIX_VME_GUEST_FEATURES = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute the SNP launch measurement for an SNP image.",
    )
    parser.add_argument("--ovmf", required=True, type=Path,
                        help="Path to the OVMF firmware binary.")
    parser.add_argument("--kernel", required=True, type=Path,
                        help="Path to the kernel image (or UKI).")
    parser.add_argument("--initrd", type=Path, default=None,
                        help="Path to the initrd. Omit for UKI inputs.")
    parser.add_argument("--cmdline", type=str, default=None,
                        help="Kernel command line. Omit for UKI inputs.")
    parser.add_argument("--vcpus", required=True, type=int,
                        help="Number of vCPUs.")
    args = parser.parse_args()

    try:
        digest = calc_launch_digest(
            mode=SevMode.SEV_SNP,
            vcpus=args.vcpus,
            vcpu_sig=FORTANIX_VME_VCPU_SIG,
            ovmf_file=str(args.ovmf),
            kernel=str(args.kernel),
            initrd=str(args.initrd) if args.initrd else None,
            append=args.cmdline,
            guest_features=FORTANIX_VME_GUEST_FEATURES,
        )
    except (RuntimeError, OSError) as e:
        print(f"Error computing launch measurement: {e}", file=sys.stderr)
        return 1

    hex_measurement = digest.hex() if isinstance(digest, (bytes, bytearray)) else str(digest)
    print(hex_measurement)
    return 0


if __name__ == "__main__":
    sys.exit(main())
