# Step 10: expect the unexpected
raw = input("Enter your employee number (digits only): ")

try:
    number = int(raw)
    print("Employee number accepted:", number)
except ValueError:
    print("That was not a number. Request denied, event logged.")