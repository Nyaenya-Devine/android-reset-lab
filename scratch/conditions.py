# Step 8: the program decides
clearance = input("Enter your clearance level (viewer/operator/admin): ")

if clearance == "admin":
    print("You may approve resets.")
elif clearance == "operator":
    print("You may request resets.")
else:
    print("You may only view the dashboard.")