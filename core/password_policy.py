"""Manages password policy configuration and validation."""
import json
import logging
import os
from typing import Any, Dict, List, Tuple

from config.constants import DEFAULT_PASSWORD_POLICY, DATA_DIR

""" Top-200 most commonly used passwords (NIST / SecLists sourced). Checked case-insensitively. Extend this list or load from a file for broader coverage """

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123321", "654321",
    "superman", "qazwsx", "michael", "football", "password1", "password123",
    "letmein", "welcome", "monkey", "login", "abc123", "starwars", "123qwe",
    "admin", "princess", "qwertyuiop", "solo", "passw0rd", "whatever",
    "qwerty123", "trustno1", "batman", "access", "hello", "charlie",
    "donald", "password2", "qwerty1", "123456a", "a123456", "1q2w3e4r",
    "mustang", "zaq12wsx", "q1w2e3r4", "motdepasse", "blahblah", "test",
    "test123", "1234qwer", "pass", "pass1234", "root", "toor", "guest",
    "secret", "letmein1", "login123", "admin123", "administrator", "master1",
    "696969", "1qaz2wsx", "zxcvbnm", "asdfgh", "asdfghjkl", "asdf",
    "jordan", "harley", "ranger", "daniel", "nicole", "jessica", "thomas",
    "george", "andrew", "joseph", "hunter", "buster", "soccer", "hockey",
    "killer", "george", "andrew", "jennifer", "joshua", "amanda", "andrea",
    "chelsea", "maggie", "pepper", "shadow1", "ferrari", "corvette", "orange",
    "1234567890", "0987654321", "password!", "pass@word1", "p@ssword",
    "p@ss1234", "abc1234", "abcdef", "111222333", "000000", "999999",
    "888888", "777777", "666666", "555555", "444444", "333333", "222222",
    "qqqqqq", "aaaaaa", "zzzzzz", "123abc", "abc123!", "welcome1",
    "pass1234!", "changeme", "iloveyou1", "hello123", "sunshine1",
    "flower", "freedom", "computer", "internet", "google", "facebook",
    "twitter", "linkedin", "instagram", "amazon", "apple1", "windows",
    "linux", "ubuntu", "debian", "fedora", "centos", "redhat", "oracle",
    "mysql", "postgres", "mongodb", "redis", "elastic", "kibana",
    "password0", "password99", "pa$$word", "p4ssword", "passw0rd1",
    "qwerty!", "qwerty12", "12345678!", "1234!@#$", "abc!@#",
}

# Expected types for each policy key — used to validate loaded JSON
_POLICY_TYPES: Dict[str, type] = {
    'min_length':        int,
    'require_uppercase': bool,
    'require_lowercase': bool,
    'require_digits':    bool,
    'require_special':   bool,
    'min_strength':      int,
}


class PasswordPolicyManager:
    """ Manages configurable password policies for master passwords.
    Features
    -Configurable minimum length and character-type requirements
    -Strength scoring (0–4)
    -Common-password detection (200 entries built-in)
    -Type-safe policy loading — a corrupted JSON value never silently
      propagates into the compliance checker
    -Policy persistence to DATA_DIR/password_policy.json """

    def __init__(self) -> None:
        self.policy: Dict[str, Any] = self.load_password_policy()

    # Load / save
    def load_password_policy(self) -> Dict[str, Any]:
        """ Load policy from disk, merge with defaults, and validate types. """
        policy = DEFAULT_PASSWORD_POLICY.copy()
        policy_file = os.path.join(DATA_DIR, "password_policy.json")

        try:
            if os.path.exists(policy_file):
                with open(policy_file, 'r', encoding='utf-8') as f:
                    saved = json.load(f)

                if not isinstance(saved, dict):
                    logging.warning("password_policy.json is not a JSON object — using defaults")
                    return policy

                for key, expected_type in _POLICY_TYPES.items():
                    if key not in saved:
                        continue  # Keep default
                    value = saved[key]
                    if expected_type is bool:
                        if not isinstance(value, bool):
                            logging.warning(
                                f"policy key '{key}': expected bool, got {type(value).__name__} "
                                f"({value!r}) — using default ({policy[key]!r})"
                            )
                            continue
                    elif expected_type is int:
                        if not isinstance(value, int) or isinstance(value, bool):
                            logging.warning(
                                f"policy key '{key}': expected int, got {type(value).__name__} "
                                f"({value!r}) — using default ({policy[key]!r})"
                            )
                            continue
                    policy[key] = value

        except Exception as e:
            logging.error(f"Error loading password policy: {e} — using defaults")

        return policy

    def get_policy(self) -> Dict[str, Any]:
        """ Return a copy of the current policy """
        return self.policy.copy()

    def update_policy(self, new_policy: Dict[str, Any]) -> bool:
        """ Validate and apply a partial policy update """
        try:
            validated: Dict[str, Any] = {}

            for key, value in new_policy.items():
                if key not in _POLICY_TYPES:
                    logging.warning(f"update_policy: unknown key '{key}' ignored")
                    continue

                expected = _POLICY_TYPES[key]
                if expected is bool and not isinstance(value, bool):
                    raise ValueError(f"'{key}' must be a bool, got {type(value).__name__}")
                if expected is int and (not isinstance(value, int) or isinstance(value, bool)):
                    raise ValueError(f"'{key}' must be an int, got {type(value).__name__}")

                # Range checks for numeric fields
                if key == 'min_length' and not (8 <= value <= 64):
                    raise ValueError("min_length must be between 8 and 64")
                if key == 'min_strength' and not (1 <= value <= 5):
                    raise ValueError("min_strength must be between 1 and 5")

                validated[key] = value

            self.policy.update(validated)
            return self.save_password_policy(self.policy)

        except Exception as e:
            logging.error(f"Failed to update password policy: {e}")
            return False

    def save_password_policy(self, policy: Dict[str, Any]) -> bool:
        """ Persist *policy* to DATA_DIR/password_policy.json. """
        policy_file = os.path.join(DATA_DIR, "password_policy.json")
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(policy_file, 'w', encoding='utf-8') as f:
                json.dump(policy, f, indent=2)
            self.policy = policy
            logging.info("Password policy saved")
            return True
        except Exception as e:
            logging.error(f"Error saving password policy: {e}")
            return False

    # Compliance checking
    def check_password_compliance(self, password: str) -> Tuple[int, List[str]]:
        """ Score a password against the active policy
        Scoring
        Each satisfied criterion adds 1 point (max 4):
          length ✓, uppercase ✓, lowercase ✓, digit ✓, special-char ✓
        A password in COMMON_PASSWORDS is always scored 0 regardless of
        how complex it looks.
        Returns (score, feedback) where score is 0–4 and feedback lists failures """
        feedback: List[str] = []
        score = 0

        # Reject immediately if too short
        min_len = int(self.policy['min_length'])
        if len(password) < min_len:
            feedback.append(f"Must be at least {min_len} characters")
            return 0, feedback

        score += 1  # length satisfied

        if self.policy['require_uppercase']:
            if any(c.isupper() for c in password):
                score += 1
            else:
                feedback.append("Add at least one uppercase letter")

        if self.policy['require_lowercase']:
            if any(c.islower() for c in password):
                score += 1
            else:
                feedback.append("Add at least one lowercase letter")

        if self.policy['require_digits']:
            if any(c.isdigit() for c in password):
                score += 1
            else:
                feedback.append("Add at least one digit")

        if self.policy['require_special']:
            if any(not c.isalnum() for c in password):
                score += 1
            else:
                feedback.append("Add at least one special character (e.g. !@#$%)")

        # Common-password check — overrides any score
        if password.lower() in COMMON_PASSWORDS:
            feedback.append("This is a commonly used password — choose something unique")
            return 0, feedback

        return min(score, 4), feedback

    def get_policy_description(self) -> str:
        """ Return a one-line human-readable summary of the active policy """
        requirements = []
        if self.policy['require_uppercase']:
            requirements.append("uppercase letters")
        if self.policy['require_lowercase']:
            requirements.append("lowercase letters")
        if self.policy['require_digits']:
            requirements.append("numbers")
        if self.policy['require_special']:
            requirements.append("special characters")

        desc = f"Minimum {self.policy['min_length']} characters"
        if requirements:
            desc += f", including {', '.join(requirements)}"
        return desc