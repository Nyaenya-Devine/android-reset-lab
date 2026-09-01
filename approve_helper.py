# approve_helper.py - the second human approves from the terminal
import sys
import getpass

import authentication
import reset_workflow

if len(sys.argv) < 2:
    print("Usage: python approve_helper.py <request_id>")
    sys.exit(1)

request_id = sys.argv[1].strip()
# Basic validation: request_id should be hex and reasonable length
if not request_id or len(request_id) > 64:
    print("Invalid request_id")
    sys.exit(1)

user = input("approver user: ").strip()
# Fix: use getpass to hide password input
password = getpass.getpass("approver pass: ")

ok, msg = authentication.login(user, password)
if not ok:
    print("login failed:", msg)
else:
    token = authentication.start_session(user)
    result = reset_workflow.approve_reset(token, request_id)
    print(result)