import unittest
import hashlib
import string
from main import *


class TestBruteForceAttack(unittest.TestCase):

    def setUp(self):
        self.app = PassCrackApp()

    def test_brute_force_attack(self):
        # Define a hash value to crack
        hash_value = "5d41402abc4b2a76b298809f844c7b2a8"

        # Define a maximum length for the generated password
        max_length = 8

        # Define a hash algorithm
        hash_algorithm = "MD5"

        # Call the brute force attack function
        cracked_password, attempts = self.app.brute_force_attack(
            hash_value, max_length, hash_algorithm
        )

        # Check if the function returns a password and the number of attempts
        self.assertIsNotNone(cracked_password)
        self.assertIsNotNone(attempts)

        # Check if the returned password is of the correct length
        self.assertEqual(len(cracked_password), max_length)

        # Check if the returned hash value matches the given hash value
        hashed_password = hashlib.md5(cracked_password.encode()).hexdigest()
        self.assertEqual(hashed_password, hash_value)


if __name__ == "__main__":
    unittest.main()
