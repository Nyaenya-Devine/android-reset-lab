# Step 9: a function is a named recipe
def check_clearance(level):
    if level == "admin":
        return "approve resets"
    elif level == "operator":
        return "request resets"
    else:
        return "view the dashboard"

user = input("Your clearance level: ")
permission = check_clearance(user)
print("You may", permission + ".")