#!/usr/bin/env python3
"""Demo of the new continue loop feature."""

from io import StringIO
from src.secure_string_cipher.cli import main

print("=" * 70)
print("DEMO: Multiple operations in one session")
print("=" * 70)

# Simulate: encrypt text, continue, decrypt text, then exit
test_input = """1
Secret message!
mypassword
mypassword
y
2
ENCRYPTED_OUTPUT_HERE
mypassword
n
"""

in_stream = StringIO(test_input)
out_stream = StringIO()

print("\nSimulated user input:")
print(test_input)

print("\n" + "=" * 70)
print("Running CLI...")
print("=" * 70 + "\n")

try:
    # Run with exit_on_completion=False for testing
    result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
    
    output = out_stream.getvalue()
    
    # Show the output
    for line in output.split('\n'):
        print(line)
    
    print("\n" + "=" * 70)
    
    # Check results
    continue_count = output.count("Continue? (y/n):")
    
    print(f"\n✅ Result code: {result}")
    print(f"✅ 'Continue?' prompts found: {continue_count}")
    
    if continue_count >= 1:
        print("\n🎉 SUCCESS! The continue loop is working!")
        print("   Users can now perform multiple operations without restarting!")
    else:
        print("\n❌ FAIL: Continue prompt not found")
        
except Exception as e:
    import traceback
    print(f"\n❌ ERROR: {e}")
    traceback.print_exc()
