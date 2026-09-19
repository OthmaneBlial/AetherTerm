"""Local operator setup. Passwords are never passed as command arguments."""

import argparse
import getpass
from pathlib import Path

from .agents import agents_file, issue_credential, revoke_device
from .auth import initialize_operator, operator_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage local AetherTerm identities")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init", help="Initialize the operator password")
    for name in ("enroll", "rotate"):
        command = subcommands.add_parser(name, help=f"{name.capitalize()} a device credential")
        command.add_argument("device_id")
        command.add_argument("--output", required=True, help="New private token-file path; must not exist")
        command.add_argument("--description", help="Optional operator-visible device description")
    revoke = subcommands.add_parser("revoke", help="Permanently revoke a device ID")
    revoke.add_argument("device_id")
    args = parser.parse_args()
    if args.command == "init":
        password = getpass.getpass("New operator password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            parser.error("Passwords do not match")
        try:
            initialize_operator(operator_file(), password)
        except FileExistsError:
            parser.error("Operator already initialized; refusing to overwrite it")
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Operator initialized in {operator_file()}")
    elif args.command in ("enroll", "rotate"):
        try:
            issue_credential(agents_file(), args.device_id, Path(args.output).expanduser(),
                             rotate=args.command == "rotate", description=args.description)
        except (FileExistsError, ValueError) as exc:
            parser.error(str(exc))
        print(f"Credential file created for {args.device_id}. Keep it private and transfer it securely to the agent.")
    elif args.command == "revoke":
        try:
            revoke_device(agents_file(), args.device_id)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Device {args.device_id} revoked.")


if __name__ == "__main__":
    main()
