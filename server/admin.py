"""Local operator setup. Passwords are never passed as command arguments."""

import argparse
import getpass

from .auth import initialize_operator, operator_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize the AetherTerm operator")
    parser.add_argument("command", choices=["init"])
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


if __name__ == "__main__":
    main()
