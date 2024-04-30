import unittest
import hashlib
from main import *


class TestDictionaryAttack(unittest.TestCase):

    def setUp(self):
        self.app = PassCrackApp()
        self.dictionary_file = "rockyou.txt"
        self.hash_value = "098f6bcd4621d373cade4e11db710e25d33a11e0f751e22c1b1b15ed8b07"

    def test_dictionary_attack_success(self):
        with open(self.dictionary_file, "r", encoding="utf-8", errors="ignore") as file:
            for word in file:
                word = word.strip()
                hashed_word = hashlib.md5(word.encode()).hexdigest()
                if hashed_word == self.hash_value:
                    self.assertEqual(
                        self.app.dictionary_attack(
                            self.hash_value, self.dictionary_file
                        ),
                        word,
                    )
                    break

    def test_dictionary_attack_failure(self):
        with open(self.dictionary_file, "r", encoding="utf-8", errors="ignore") as file:
            for word in file:
                word = word.strip()
                hashed_word = hashlib.md5(word.encode()).hexdigest()
                if hashed_word != self.hash_value:
                    self.assertNotEqual(
                        self.app.dictionary_attack(
                            self.hash_value, self.dictionary_file
                        ),
                        word,
                    )


if __name__ == "__main__":
    unittest.main()
