from typing import Generator, Dict, Any

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class PasswordHashingIterationsTooLow(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Password hashing iterations too low"
    LONG_DESCRIPTION = (
        "The number of iterations used for password hashing is too low, which makes password hashes "
        "more vulnerable to brute force attacks. The recommended minimum values are: "
        "pbkdf2-sha512: 210,000; pbkdf2-sha256: 600,000; pbkdf2: 1,300,000. "
        "This check is not applicable to argon2 algorithm."
    )
    REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"

    # Minimum recommended iterations for each algorithm
    MINIMUM_ITERATIONS: Dict[str, int] = {
        "pbkdf2-sha512": 210_000,
        "pbkdf2-sha256": 600_000,
        "pbkdf2": 1_300_000,
    }

    def extract_password_policy(self, realm: Realm) -> Dict[str, str]:
        """Extract password policy settings from realm configuration."""
        policy_str: str = realm.get_password_policy()
        if not policy_str:
            return {}

        policy_dict: Dict[str, str] = {}
        for policy in policy_str.split(" and "):
            if "(" in policy and ")" in policy:
                # Format is like: hashAlgorithm(pbkdf2-sha256)
                key, value = policy.split("(", 1)
                value = value.rstrip(")")
                policy_dict[key.strip()] = value.strip()
            elif ":" in policy:
                # Alternative format with colon
                key, value = policy.split(":", 1)
                policy_dict[key.strip()] = value.strip()
            else:
                policy_dict[policy.strip()] = "enabled"

        return policy_dict

    def get_hashing_algorithm(self, realm: Realm) -> str | None:
        """Get the password hashing algorithm from realm configuration."""
        policy = self.extract_password_policy(realm)
        if "hashAlgorithm" in policy:
            return policy["hashAlgorithm"]

        # If not defined in password policy, check if it's defined elsewhere in the realm
        password_hash_algorithm = realm.get_password_hash_algorithm()
        if password_hash_algorithm != "":
            return password_hash_algorithm

        # Default algorithm is pbkdf2 if not specified
        return "pbkdf2"

    def get_hashing_iterations(self, realm: Realm) -> int | None:
        """Get the number of password hashing iterations from realm configuration."""
        policy = self.extract_password_policy(realm)
        if "hashIterations" in policy:
            try:
                return int(policy["hashIterations"])
            except (ValueError, TypeError):
                return None

        # If not defined in password policy, check if it's defined elsewhere in the realm
        password_hash_iterations = realm.get_password_hash_iterations()
        if password_hash_iterations != "":
            try:
                return int(password_hash_iterations)
            except (ValueError, TypeError):
                return None

        # Return None if no iterations are defined (will use default based on algorithm)
        return None

    def is_iterations_too_low(self, realm: Realm) -> bool:
        """Check if the number of hashing iterations is too low."""
        algorithm: str | None = self.get_hashing_algorithm(realm)
        iterations: int | None = self.get_hashing_iterations(realm)

        # Skip check for argon2 algorithm
        if algorithm and "argon2" in algorithm.lower():
            return False

        # If algorithm is not recognized or iterations is not defined, assume it's using defaults
        if algorithm is None or iterations is None:
            return False

        # Check if iterations are below the minimum for the algorithm
        for alg_name, min_iterations in self.MINIMUM_ITERATIONS.items():
            if alg_name.lower() in algorithm.lower():
                return iterations < min_iterations

        # If algorithm doesn't match any known ones but is a pbkdf2 variant, use pbkdf2 minimum
        if "pbkdf2" in algorithm.lower():
            return iterations < self.MINIMUM_ITERATIONS["pbkdf2"]

        # For unknown algorithms, don't flag
        return False

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.is_iterations_too_low(realm):
            algorithm: str | None = self.get_hashing_algorithm(realm)
            iterations: int | None = self.get_hashing_iterations(realm)

            # Determine which minimum applies
            applicable_minimum = None
            for alg_name, min_iterations in self.MINIMUM_ITERATIONS.items():
                if algorithm and alg_name.lower() in algorithm.lower():
                    applicable_minimum = min_iterations
                    break

            # If no specific algorithm matched but it's a pbkdf2 variant, use pbkdf2 minimum
            if applicable_minimum is None and algorithm and "pbkdf2" in algorithm.lower():
                applicable_minimum = self.MINIMUM_ITERATIONS["pbkdf2"]

            additional_details: Dict[str, Any] = {
                "algorithm": algorithm,
                "current_iterations": iterations,
                "minimum_recommended_iterations": applicable_minimum,
            }

            yield self.generate_finding(realm, additional_details)
