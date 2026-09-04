"""
Reset or wipe user database files.

Usage
-----
  python reset_db.py                  # interactive: lists users, asks which to reset
  python reset_db.py alice            # reset a specific user
  python reset_db.py --all            # reset every user (prompts for confirmation)
  python reset_db.py --list           # just list users, do nothing

WARNING: This permanently deletes password data. Back up first.
"""
import argparse
import glob
import json
import os
import sys

from config.constants import DATA_DIR


def list_users(data_dir: str) -> list[str]:
    """Return all usernames that have a database file in data_dir."""
    pattern = os.path.join(data_dir, "user_*.db")
    paths   = glob.glob(pattern)
    return [os.path.basename(p)[5:-3] for p in sorted(paths)]  # strip "user_" prefix and ".db"


def reset_user(username: str, data_dir: str) -> bool:
    """
    Delete and recreate a user's database file as an empty list.
    Also removes the user from profiles.json and salts.json so they
    can re-register cleanly.
    """
    db_path = os.path.join(data_dir, f"user_{username}.db")

    # Reset database file
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"  Removed: {db_path}")
    with open(db_path, 'w', encoding='utf-8') as f:
        json.dump([], f)
    print(f"  Created empty database: {db_path}")

    # Remove from profiles.json
    profiles_path = os.path.join(data_dir, "profiles.json")
    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, 'r', encoding='utf-8') as f:
                profiles = json.load(f)
            if username in profiles:
                del profiles[username]
                with open(profiles_path, 'w', encoding='utf-8') as f:
                    json.dump(profiles, f, indent=2)
                print(f"  Removed '{username}' from profiles.json")
        except Exception as e:
            print(f"  Warning: could not update profiles.json: {e}")

    # Remove from salts.json
    salts_path = os.path.join(data_dir, "salts.json")
    if os.path.exists(salts_path):
        try:
            with open(salts_path, 'r', encoding='utf-8') as f:
                salts = json.load(f)
            if username in salts:
                del salts[username]
                with open(salts_path, 'w', encoding='utf-8') as f:
                    json.dump(salts, f, indent=2)
                print(f"  Removed '{username}' from salts.json")
        except Exception as e:
            print(f"  Warning: could not update salts.json: {e}")

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset PM2 user databases")
    group  = parser.add_mutually_exclusive_group()
    group.add_argument('username', nargs='?', help="Username to reset")
    group.add_argument('--all',  action='store_true', help="Reset ALL users")
    group.add_argument('--list', action='store_true', help="List users and exit")
    args = parser.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    users = list_users(DATA_DIR)

    if args.list:
        if users:
            print("Users found:")
            for u in users:
                print(f"  • {u}")
        else:
            print("No user databases found.")
        return

    if not users:
        print("No user databases found. Nothing to reset.")
        return

    if args.all:
        print(f"This will permanently delete data for: {', '.join(users)}")
        confirm = input("Type YES to confirm: ").strip()
        if confirm != "YES":
            print("Aborted.")
            return
        for u in users:
            print(f"\nResetting '{u}'...")
            reset_user(u, DATA_DIR)
        print("\nAll users reset.")
        return

    if args.username:
        target = args.username
    else:
        # Interactive mode
        print("Users found:")
        for i, u in enumerate(users, 1):
            print(f"  {i}. {u}")
        choice = input("\nEnter username or number to reset (q to quit): ").strip()
        if choice.lower() == 'q':
            return
        if choice.isdigit() and 1 <= int(choice) <= len(users):
            target = users[int(choice) - 1]
        else:
            target = choice

    if target not in users:
        print(f"No database found for user '{target}'. Available: {users or 'none'}")
        sys.exit(1)

    confirm = input(f"Reset '{target}'? This cannot be undone. (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Aborted.")
        return

    print(f"\nResetting '{target}'...")
    reset_user(target, DATA_DIR)
    print("Done.")


if __name__ == "__main__":
    main()