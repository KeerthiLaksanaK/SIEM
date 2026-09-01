import random
import time
import requests

TARGET = "http://127.0.0.1:5000/lab/status"

# Random request count:
# 10-19 -> normally NO alert
# 20-30 -> SHOULD generate alert
REQUEST_COUNT = random.randint(10, 30)

# Random total duration:
# 20-55 seconds, always inside the 1-minute detection window
TOTAL_DURATION = random.randint(20, 55)

print("=" * 60)
print("        SIEM HTTP TRAFFIC LAB")
print("=" * 60)

print("\nStarting controlled HTTP traffic...\n")

start_time = time.time()
success = 0

for i in range(REQUEST_COUNT):

    # Remaining requests after this one
    remaining = REQUEST_COUNT - i

    # Send request
    try:
        response = requests.get(
            TARGET,
            timeout=5
        )

        success += 1

        # Show only basic request activity.
        # Do NOT reveal total request count or elapsed time.
        print(
            f"Request {i + 1:02d} | "
            f"HTTP {response.status_code}"
        )

    except requests.RequestException:
        print(
            f"Request {i + 1:02d} | "
            f"Request failed"
        )

    # Don't sleep after the final request
    if i == REQUEST_COUNT - 1:
        break

    # Calculate remaining time
    elapsed = time.time() - start_time
    remaining_time = max(0, TOTAL_DURATION - elapsed)

    # Spread remaining requests across remaining time
    if remaining > 0:

        base_delay = remaining_time / remaining

        # Randomize the delay
        variation = random.uniform(0.60, 1.40)

        delay = base_delay * variation

        # Prevent the test from exceeding the selected duration
        max_delay = max(
            0.1,
            remaining_time - 0.1 * (remaining - 1)
        )

        delay = min(delay, max_delay)

        time.sleep(delay)


print("\n" + "=" * 60)
print("HTTP TRAFFIC TEST COMPLETED")
print("=" * 60)

print("\nTraffic generation finished.")