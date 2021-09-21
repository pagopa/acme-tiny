#!/usr/bin/env python3

import argparse
import base64
import os
import sys
import textwrap


def env_to_file(env_name, out, base64_encoded):
    env_value = os.environ[env_name]
    if base64_encoded is True:
        env_value = base64.b64decode(env_value).decode("utf-8")
    with open(out, "w") as f:
        f.write(env_value)


def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script prints out to file an environment variable

            Example Usage:
            python3 env_to_file.py --env-name MESSAGE csr.key --out message.txt
            """)
    )
    parser.add_argument("--env-name", required=True,
                        help="Environment variable name")
    parser.add_argument("--base64", action="store_const", const=True)
    parser.add_argument("--out", required=True,
                        help="Output file")
    args = parser.parse_args(argv)
    env_to_file(args.env_name, args.out, args.base64)


if __name__ == '__main__':
    main(sys.argv[1:])
