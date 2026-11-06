"""Command-line tools.

Create the first admin account (there is no default password anywhere):

    docker compose run --rm api python -m app.cli create-admin --email you@gmail.com
"""

import argparse
import sys
from getpass import getpass

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import record
from app.db import get_engine
from app.models import Role, User
from app.schemas import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, UserCreate
from app.security.passwords import hash_password


def create_admin(email: str) -> int:
    password = getpass(f"New admin password ({PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters): ")
    if password != getpass("Repeat the password: "):
        print("Passwords do not match. Nothing was created.", file=sys.stderr)
        return 1

    try:
        data = UserCreate(email=email, password=password, role=Role.ADMIN)
    except ValidationError as exc:
        for error in exc.errors():
            # Print the field and the rule, never the password itself.
            print(f"Invalid {error['loc'][0]}: {error['msg']}", file=sys.stderr)
        return 1

    normalized_email = str(data.email).lower()
    with Session(get_engine()) as db:
        if db.scalar(select(User.id).where(User.email == normalized_email)) is not None:
            print("A user with this email already exists. Nothing was created.", file=sys.stderr)
            return 1
        user = User(email=normalized_email, password_hash=hash_password(data.password), role=Role.ADMIN)
        db.add(user)
        db.flush()
        record(
            db,
            "user.created",
            user_id=user.id,
            object_type="user",
            object_id=str(user.id),
            details={"via": "cli", "role": Role.ADMIN.value},
        )
        db.commit()

    print(f"Admin account created for {normalized_email}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="SentinelQA admin tools")
    commands = parser.add_subparsers(dest="command", required=True)
    admin_parser = commands.add_parser("create-admin", help="Create an administrator account")
    admin_parser.add_argument("--email", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "create-admin":
            return create_admin(args.email)
    except (KeyboardInterrupt, EOFError):
        # Ctrl+C / Ctrl+D at a password prompt: stop cleanly, nothing was saved.
        print("\nCancelled. Nothing was created.", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    sys.exit(main())
