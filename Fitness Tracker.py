import hashlib
import os

class User:
    def __init__(self, **kwargs):
        self.username = kwargs.get('username')
        self.name = kwargs.get('name')
        self.password_hash = kwargs.get('password_hash')
        self.age = kwargs.get('age')
        self.weight = kwargs.get('weight')
        self.height = kwargs.get('height')
        self.fitness_goals = kwargs.get('fitness_goals', {})
        self.activities = kwargs.get('activities', [])
        self.workouts = kwargs.get('workouts', [])
        self.nutrition_logs = kwargs.get('nutrition_logs', [])

    def log_activity(self, activity):
        self.activities.append(activity)

    def log_workout(self, workout):
        self.workouts.append(workout)

    def log_nutrition(self, nutrition_log):
        self.nutrition_logs.append(nutrition_log)

class FitnessTracker:
    def __init__(self):
        self.users = {}
        self.logged_in_user = None
        self.load_user_data()

    def create_account(self):
        username = input("Enter user ID: ")
        name = input("Enter your name: ")
        age = int(input("Enter your age: "))
        weight = float(input("Enter your weight (in kg): "))
        height = float(input("Enter your height (in cm): "))
        password = input("Enter password: ")

        if username in self.users:
            print("Username already exists. Please choose another username.")
        else:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            self.users[username] = User(username=username, name=name, password_hash=password_hash, age=age, weight=weight, height=height)
            print("Account created successfully.")

    def login(self):
        self.load_user_data()  # Load user data from file before login
        username = input("Enter user ID: ")
        password = input("Enter password: ")
        if username in self.users:
            user = self.users[username]
            if user.password_hash == hashlib.sha256(password.encode()).hexdigest():
                self.logged_in_user = user
                print("Login successful.")
                return
        print("Invalid username or password.")

    def logout(self):
        self.logged_in_user = None
        print("Logged out successfully.")

    def save_user_data(self):
        with open(f"fitness.txt", "w") as file:
            for user in self.users.values():
                file.write(f"Username: {user.username}\n")
                file.write(f"Name: {user.name}\n")
                file.write(f"Age: {user.age}\n")
                file.write(f"Weight: {user.weight}\n")
                file.write(f"Height: {user.height}\n")
                file.write(f"Password Hash: {user.password_hash}\n")  # Save password hash
                file.write("Fitness Goals:\n")
                for goal_type, goal in user.fitness_goals.items():
                    file.write(f"{goal_type}: {goal}\n")
                file.write("Logged Activities:\n")
                for activity in user.activities:
                    file.write(f"{activity}\n")
                file.write("Logged Workouts:\n")
                for workout in user.workouts:
                    file.write(f"{workout}\n")
                file.write("Logged Nutrition Logs:\n")
                for log in user.nutrition_logs:
                    file.write(f"{log}\n")
                file.write("\n")
        print("User data saved to file.")

    def load_user_data(self):
        if os.path.exists("fitness.txt"):
            with open("fitness.txt", "r") as file:
                lines = file.readlines()
                current_user_data = {}
                current_category = None
                for line in lines:
                    line = line.strip()
                    if line.startswith("Username:"):
                        if current_user_data:
                            if "username" in current_user_data and "password_hash" in current_user_data:
                                user = User(**current_user_data)
                                self.users[user.username] = user
                            current_user_data = {}
                        current_user_data["username"] = line.split(":")[1].strip()
                    elif line.startswith("Name:"):
                        current_user_data["name"] = line.split(":")[1].strip()
                    elif line.startswith("Age:"):
                        current_user_data["age"] = int(line.split(":")[1].strip())
                    elif line.startswith("Weight:"):
                        current_user_data["weight"] = float(line.split(":")[1].strip())
                    elif line.startswith("Height:"):
                        current_user_data["height"] = float(line.split(":")[1].strip())
                    elif line.startswith("Password Hash:"):
                        current_user_data["password_hash"] = line.split(":")[1].strip()
                    elif line.startswith("Fitness Goals:"):
                        current_category = "fitness_goals"
                        current_user_data[current_category] = {}
                    elif line.startswith("Logged Activities:"):
                        current_category = "activities"
                        current_user_data[current_category] = []
                    elif line.startswith("Logged Workouts:"):
                        current_category = "workouts"
                        current_user_data[current_category] = []
                    elif line.startswith("Logged Nutrition Logs:"):
                        current_category = "nutrition_logs"
                        current_user_data[current_category] = []
                    elif line and current_category:
                        if current_category == "fitness_goals":
                            goal_type, goal = line.split(":")
                            current_user_data[current_category][goal_type.strip()] = goal.strip()
                        else:
                            current_user_data[current_category].append(line)
        if current_user_data:
            if "username" in current_user_data and "password_hash" in current_user_data:
                user = User(**current_user_data)
                self.users[user.username] = user

def main():
    tracker = FitnessTracker()

    while True:
        print("\nFitness Tracker Menu:")
        print("1. Create Account")
        print("2. Login")
        print("3. Logout")
        print("4. Log Activity")
        print("5. Log Workout")
        print("6. Log Nutrition")
        print("7. View All User Inputs")
        print("8. Save User Data")
        print("9. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            tracker.create_account()

        elif choice == "2":
            if tracker.logged_in_user:
                print("You are already logged in. Please logout first.")
            else:
                tracker.login()

        elif choice == "3":
            tracker.logout()

        elif choice == "4":
            if tracker.logged_in_user:
                activity = input("Enter activity: ")
                tracker.logged_in_user.log_activity(activity)
                print("Activity logged.")
            else:
                print("Please login first.")

        elif choice == "5":
            if tracker.logged_in_user:
                workout = input("Enter workout details: ")
                tracker.logged_in_user.log_workout(workout)
                print("Workout logged.")
            else:
                print("Please login first.")

        elif choice == "6":
            if tracker.logged_in_user:
                nutrition_log = input("Enter nutrition log: ")
                tracker.logged_in_user.log_nutrition(nutrition_log)
                print("Nutrition logged.")
            else:
                print("Please login first.")

        elif choice == "7":
            if tracker.logged_in_user:
                print("\nAll User Inputs:")
                print("Username:", tracker.logged_in_user.username)
                print("Name:", tracker.logged_in_user.name)
                print("Age:", tracker.logged_in_user.age)
                print("Weight:", tracker.logged_in_user.weight)
                print("Height:", tracker.logged_in_user.height)
                print("Fitness Goals:")
                for goal_type, goal in tracker.logged_in_user.fitness_goals.items():
                    print(f"{goal_type}: {goal}")
                print("Logged Activities:")
                for activity in tracker.logged_in_user.activities:
                    print(activity)
                print("Logged Workouts:")
                for workout in tracker.logged_in_user.workouts:
                    print(workout)
                print("Logged Nutrition Logs:")
                for log in tracker.logged_in_user.nutrition_logs:
                    print(log)
            else:
                print("Please login first.")

        elif choice == "8":
            if tracker.logged_in_user:
                tracker.save_user_data()
            else:
                print("Please login first.")

        elif choice == "9":
            if tracker.logged_in_user:
                tracker.save_user_data()
            print("Exiting program...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
