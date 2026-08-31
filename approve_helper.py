# approve_helper.py - the second human approves from the terminal
import sys

import authentication
import reset_workflow

request_id = sys.argv[1]
user = input("approver user: ")
password = input("approver pass: ")
ok, msg = authentication.login(user, password)
if not ok:
    print("login failed:", msg)
else:
    token = authentication.start_session(user)
    print(reset_workflow.approve_reset(token, request_id))