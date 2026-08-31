# Step 11: files outlive the program
with open("scratch/notes.txt", "w") as f:
    f.write("Event: operator logged in\n")
    f.write("Event: reset requested\n")

with open("scratch/notes.txt", "r") as f:
    content = f.read()

print("The file contains:")
print(content)