#!/usr/bin/env python3
"""
User management CLI for hermes-multiuser-proxy.

Usage:
    python manage.py create  <username> <password> <profile> [role]
    python manage.py update  <username> [--password PW] [--profile PF] [--role ROLE]
    python manage.py delete  <username>
    python manage.py list
"""
import argparse
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

import users


def cmd_create(args):
    role = args.role or "user"
    if role not in ("admin", "user"):
        print(f"❌ Invalid role: {role} (must be admin or user)")
        sys.exit(1)
    if users.create_user(args.username, args.password, args.profile, role):
        print(f"✅ User '{args.username}' created (profile={args.profile}, role={role})")
    else:
        print(f"❌ User '{args.username}' already exists")
        sys.exit(1)


def cmd_update(args):
    kwargs = {}
    if args.password:
        kwargs["password"] = args.password
    if args.profile:
        kwargs["profile"] = args.profile
    if args.role:
        if args.role not in ("admin", "user"):
            print(f"❌ Invalid role: {args.role}")
            sys.exit(1)
        kwargs["role"] = args.role

    if not kwargs:
        print("❌ Nothing to update. Use --password, --profile, or --role")
        sys.exit(1)

    if users.update_user(args.username, **kwargs):
        print(f"✅ User '{args.username}' updated")
    else:
        print(f"❌ User '{args.username}' not found")
        sys.exit(1)


def cmd_delete(args):
    if users.delete_user(args.username):
        print(f"✅ User '{args.username}' deleted")
    else:
        print(f"❌ User '{args.username}' not found")
        sys.exit(1)


def cmd_list(args):
    all_users = users.list_users()
    if not all_users:
        print("No users configured.")
        return
    print(f"{'Username':<15} {'Profile':<25} {'Role':<8} {'Created'}")
    print("-" * 70)
    for uname, info in all_users.items():
        print(f"{uname:<15} {info['profile']:<25} {info['role']:<8} {info.get('created_at', '-')}")


def main():
    parser = argparse.ArgumentParser(description="Manage proxy users")
    sub = parser.add_subparsers(dest="command")

    # create
    p_create = sub.add_parser("create", help="Create a new user")
    p_create.add_argument("username")
    p_create.add_argument("password")
    p_create.add_argument("profile", help="Hermes profile name to bind")
    p_create.add_argument("role", nargs="?", default="user", help="admin or user (default: user)")

    # update
    p_update = sub.add_parser("update", help="Update an existing user")
    p_update.add_argument("username")
    p_update.add_argument("--password", "-p")
    p_update.add_argument("--profile")
    p_update.add_argument("--role")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a user")
    p_delete.add_argument("username")

    # list
    sub.add_parser("list", help="List all users")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmds = {
        "create": cmd_create,
        "update": cmd_update,
        "delete": cmd_delete,
        "list": cmd_list,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
