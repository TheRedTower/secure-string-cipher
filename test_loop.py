#!/usr/bin/env python3
"""Quick test of the new continue loop."""

from io import StringIO
from secure_string_cipher.cli import main
import traceback

# Simulate: encrypt text, then say no to continue
test_input = """1
hello world
test123
test123
n
"""

in_stream = StringIO(test_input)
out_stream = StringIO()

try:
    result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)

    output = out_stream.getvalue()
    print("Output:")
    print(output)
    print("\nResult code:", result)

    # Check for "Continue?" prompt
    if "Continue?" in output:
        print("✅ Continue loop is working!")
    else:
        print("❌ Continue prompt not found")
except Exception as e:
    print("❌ Error:", e)
    traceback.print_exc()
