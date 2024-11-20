from datetime import datetime


# Open the log file for reading
with open('auth2.log.txt', 'r') as file:
	#log_data = file.readlines()
	# Lists to hold parsed data
	commands = []
	user_adds = []
	user_dels = []
	passwd_changes = []
	su_commands = []
	failed_sudo = []

	# Parsing the log data
	for line in file:
		# Look for sudo command usage
		if "sudo:" in line:
			timestamp = line[:15].strip()
			if "USER=" in line:
				user = line.split("USER=")[1].split(";")[0]
			if "COMMAND=/usr/bin/" in line:
				command = line.split("COMMAND=/usr/bin/")[-1].strip()
			new_command = {"timestamp": timestamp, "user": user, "command": command}
			if new_command not in commands:
				commands.append(new_command)
		
		# Look for user additiSons (useradd)
		if "useradd" in line:
			timestamp = line[:15].strip()
			if ("useradd" in line) and ( "failed" not in line)and ( "/etc/passwd" not in line):
				user = line.split("name=")[1].split(",")[0]
			new_useradd = {"timestamp": timestamp, "user": user}
			if new_useradd not in user_adds:
				user_adds.append(new_useradd)
		
		# Look for user deletions (userdel)
		if "userdel" in line:
			timestamp = line[:15].strip()
			user = line.split()[-1]
			new_userdel = {"timestamp": timestamp, "user": user}
			if new_userdel not in user_dels:
				user_dels.append(new_userdel)
		
		# Look for password changes
		if "passwd:" in line:
			timestamp = line[:15].strip()
			user = line.split()[-1]
			new_passwd = {"timestamp": timestamp, "user": user}
			if new_passwd not in passwd_changes:
				passwd_changes.append(new_passwd)
		
		# Look for su command usage
		if "su:" in line:
			timestamp = line[:15].strip()
			if "USER=" in line:
				user = line.split("USER=")[1].split(";")[0]
			new_su_command = {"timestamp": timestamp, "user": user}
			if new_su_command not in su_commands:
				su_commands.append(new_su_command)

		# Look for failed sudo attempts
		if "sudo:" in line and "failed" in line.lower():
			failed_sudo.append(line.strip())

	# Printing results
	print("||=====>> User Authentication & Command Logs <<=====||\n")

	# Newly added users
	print("||=====>> Newly Added Users:")
	if user_adds:
		for user_add in user_adds:
			print(f"New User Added: {user_add['user']} at {user_add['timestamp']}")
		print("\n")
	else:
		print("Ooops! No New Users Added!\n")

	# Deleted users
	print("||=====>> Deleted Users:")
	if user_dels:
		for user_del in user_dels:
			print(f"User Deleted: {user_del['user']} at {user_del['timestamp']}")
		print("\n")
	else:
		print("Ooops! No Deleted Users!\n")

	# Password changes
	print("||=====>> Password Changes:")
	if passwd_changes:
		for passwd_change in passwd_changes:
			print(f"Password Changed for {passwd_change['user']} at {passwd_change['timestamp']}")
		print("\n")
	else:
		print("Ooops! No Password Changes!\n")

	# Users who used the su command
	print("||=====>> Users Who Used The SU Command:")
	if su_commands:
		for su_command in su_commands:
			print(f"User {su_command['user']} used the su command at {su_command['timestamp']}")
		print("\n")
	else:
		print("Ooops! No Users Who Used The SU Command!\n")

	# Sudo commands used by users
	print("||=====>> Sudo Commands Used By Users:")
	if commands:
		for command in commands:
			print(f"User {command['user']} used sudo command '{command['command']}' at {command['timestamp']}")
		print("\n")
	else:
		print("Ooops! No Sudo Commands Used By Users!\n")

	# Failed sudo attempts
	print("||=====>> Failed Sudo Attempts:")
	if failed_sudo:
		for failed in failed_sudo:
			print(f"ALERT! Failed sudo attempt: {failed}")
		print("\n")
	else:
		print("Ooops! No Failed Sudo Attempts!\n")
	
	
	
	
