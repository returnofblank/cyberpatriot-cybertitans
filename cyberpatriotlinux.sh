#!/bin/bash

if [[ "$EUID" -ne 0 ]]; then
	echo "This script is running without root privileges, which is not possible. Exiting"
	exit 0
fi

# Package name to check
PACKAGE_NAME="dialog"

# Check if the package is installed
dpkg --get-selections | grep -q $PACKAGE_NAME > /dev/null
if [[ $? -ne 0 ]]; then
	echo "The package $PACKAGE_NAME is not installed."
	apt -y install $PACKAGE_NAME
fi

# Package name to check
PACKAGE_NAME="xterm"

# Check if the package is installed
dpkg --get-selections | grep -q $PACKAGE_NAME > /dev/null
if [[ $? -ne 0 ]]; then
	echo "The package $PACKAGE_NAME is not installed."
	apt -y install $PACKAGE_NAME
fi

# Package name to check
PACKAGE_NAME="curl"

# Check if the package is installed
dpkg --get-selections | grep -q $PACKAGE_NAME > /dev/null
if [[ $? -ne 0 ]]; then
	echo "The package $PACKAGE_NAME is not installed."
	apt -y install $PACKAGE_NAME
fi

#Enable distro agnostic identification of administrators
if [[ -f /etc/os-release ]]; then
		source /etc/os-release
	if [[ $ID == "debian" || $ID_LIKE == "debian" ]]; then
		group_name="sudo"
	else
		group_name="wheel"
	fi
else
	# Fallback to "wheel" if /etc/os-release is not available
	group_name="wheel"
fi

dialog --msgbox "This is not a comprehensive utility; many operations will still have to be done manually!" 0 0

# Functions for display management options
user_management_menu() {
	userm=$(dialog --checklist "Select what user management you want done: " 0 0 0 --output-fd 1 \
		1 "Replace passwords of administrators" off \
		2 "Manage users with administrator privileges" off \
		3 "Remove unauthorized users" off \
		4 "Remove potentially hidden users" off \
		5 "Disable root login" off \
		6 "Enable password policy practices" off \
		7 "Disable guest account, if present" off \
		8 "Enable screen-lock for current user" off
		)
	# Run commands based on output of dialog
	for option in $userm; do
		if [ "$option" == 1 ]; then
			sudo_users=$(getent group $group_name | cut -d : -f 4)
			IFS=',' read -ra sudo_user_array <<< "$sudo_users"

			# Concatenate all of the username and password pairs into a single string
			password_list=""
			for users in "${sudo_user_array[@]}"; do
				if [ "$users" = $(logname) ]; then
					# Skip the current user
					continue
				fi
					# Generate a random password
					password=$(tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 13; echo)

					# Change the user's password
					echo "$users":"$password" | chpasswd

					# Add the username and password pair to the password list
					password_list="$password_list$users:$password\n"
					# Make a file with all the changed passwords (insecure but whatever, this is not meant to run outside of Cyber Patriot)
					echo -e "$password_list\n" >> ./changedpasswords.txt
			done
			# Display the password list in a single msgbox
			dialog --title "New Passwords for Admins" --msgbox "$password_list" 0 0
		fi
		if [ "$option" == 2 ]; then
			# Use dialog to prompt the user for a list of usernames
			usernames=$(dialog --title "User Management - Sudo Group" --inputbox "Enter a list of usernames (comma-separated, no spaces) who should be in the sudo group:" 0 0 --output-fd 1)
			if [[ -z "${usernames// }" ]]; then
				dialog --title "User Management - Sudo Group" --msgbox "No changes were made. Usernames were not provided." 0 0
			else
				current_sudo_users=($(getent group $group_name | cut -d ':' -f 4 | tr ',' ' '))

				# Convert the input to an array
				IFS=',' read -ra user_array <<< "$usernames"

				# Initialize arrays for users to be added and removed
				users_to_add=()
				users_to_remove=()

				# Iterate through the user array
				for user in "${user_array[@]}"; do
				# Check if the user is already in the sudo group or if it's the current user
					if [[ " ${current_sudo_users[*]} " =~ " $user " || "$user" == $(logname) ]]; then
						continue
					else
						users_to_add+=("$user")
					fi
				done

				# Iterate through the current sudo users to find those to remove
				for user in "${current_sudo_users[@]}"; do
					if [[ ! " ${user_array[*]} " =~ " $user " && "$user" != $(logname) ]]; then
						users_to_remove+=("$user")
					fi
				done

				# Add new users to the sudo group
				for user in "${users_to_add[@]}"; do
					usermod -aG "$group_name" "$user" >/dev/null
				done

				# Remove users from the sudo group
				for user in "${users_to_remove[@]}"; do
					deluser "$user" "$group_name" >/dev/null
					deluser "$user" adm >/dev/null
					deluser "$user" admin >/dev/null
				done

				# Display the changes made using dialog
				add_msg="Users added to sudo group: ${users_to_add[*]}"
				remove_msg="Users removed from sudo group: ${users_to_remove[*]}"
				dialog --title "User Management - Sudo Group" --msgbox "$add_msg\n$remove_msg" 0 0
			fi
		fi
		if [ "$option" == 3 ]; then
			# Get a list of real users on the system
			users=$(awk -F: '$3 >= 1000 && $1 != "'"$(logname)"'" && $1 != "nobody" { print $1 }' /etc/passwd)

			# Convert the user list into an array
			user_array=()
			for user in $users; do
				user_array+=($user)
			done

			# Sort the user array
			IFS=$'\n' sorted_user_array=($(sort <<<"${user_array[*]}"))
			unset IFS

			# Add "off" after each username
			final_user_array=()
			for user in "${sorted_user_array[@]}"; do
				final_user_array+=($user "" off)
			done

			# Use dialog to prompt the user for a list of usernames TO DELETE!!!
			usernames=$(dialog --title "User Management - Delete Users" --checklist "Select usernames who should be DELETED (Refer to readme to compare):" 0 0 0 "${final_user_array[@]}" --output-fd 1)
			user_list=""
			for user in $usernames; do
				deluser "$user" >/dev/null
				user_list="$user_list$user\n"
			done
			dialog --title "User Management - Deleted users" --msgbox "$user_list" 0 0
		fi
		if [ "$option" == 4 ]; then
			# Get a list of users on the system
			users=$(awk -F: '$3 < 1000 && $1 != "nobody" { print $1 }' /etc/passwd)

			# Convert the user list into an array
			user_array=()
			for user in $users; do
				user_array+=($user)
			done

			# Sort the user array
			IFS=$'\n' sorted_user_array=($(sort <<<"${user_array[*]}"))
			unset IFS

			# Add "off" after each username
			final_user_array=()
			for user in "${sorted_user_array[@]}"; do
				final_user_array+=($user "" off)
			done

			# Use dialog to prompt the user for a list of usernames TO DELETE!!!
			usernames=$(dialog --title "User Management - Delete Hidden Users" --checklist "Select hidden users who should be DELETED:" 0 0 0 "${final_user_array[@]}" --output-fd 1)
			user_list=""
			for user in $usernames; do
				sed -i "/${user}/d" /etc/passwd
				sed -i "/${user}/d" /etc/shadow
				sed -i "/${user}/d" /etc/group
				sed -i "/${user}/d" /etc/gshadow
				user_list="$user_list$user\n"
			done
			dialog --title "User Management - Deleted users" --msgbox "$user_list" 0 0
		fi
		if [ "$option" == 5 ]; then
			sed -i "/^root:/s:/bin/bash:/sbin/nologin:g" /etc/passwd
			dialog --title "User Management - Root Disabled" --msgbox "Login no longer enabled for Root user" 0 0
		fi
		if [ "$option" == 6 ]; then
			echo -e "minlen = 14\nucredit = -1\nlcredit = -1\nocredit = -1\ndcredit = -1\nusercheck=1" >> /etc/security/pwquality.conf
			sed -i '/pam_unix.so/s/ sha.*//'
			sed -i '/pam_unix.so/ s/$/ remember=5 minlen=14 sha512/' /etc/pam.d/common-password
			sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
			sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs
			sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
			echo "auth    required    pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
			dialog --title "User Management - Password Policy" --msgbox "All passwords require 14 characters and require uppercase, lowercase, digits, and special characters" 0 0
		fi
		if [ "$option" == 7 ]; then
			echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
			dialog --title "User Management - Guest Account" --msgbox "Guest account disabled, if present" 0 0
		fi
		if [ "$option" == 8 ]; then
			sudo -u "$(logname)" gsettings set org.gnome.desktop.session idle-delay 300 2> /dev/null
			sudo -u "$(logname)" xset s 300 2> /dev/null
			sudo -u "$(logname)" gsettings get org.gnome.desktop.screensaver lock-enabled true
			sudo -u "$(logname)" gsettings set org.gnome.desktop.screensaver lock-delay 0
			dialog --title "User Management - Various Tweaks" --msgbox "Enabled various tweaks!" 0 0
		fi
	done
}
package_management_menu (){
	packagem=$(dialog --checklist "Select what package operations you want done: " 0 0 0 --output-fd 1 \
		1 "Update system repositories" off \
		2 "Upgrade system packages" off \
		3 "Enable automatic updates" off \
		4 "Remove potential hacking tools and games" off \
		5 "Remove manually installed packages" off \
		6 "List packages with a hold set on them" off \
		7 "Launch stacer for repository management" off
		)
	# Run commands based on output of dialog
	for option in $packagem; do
		if [ "$option" == 1 ]; then
			dialog --title "Package Operations" --infobox "Updating system repositories" 0 0
			xterm -e 'apt update' &
			dialog --title "Package Operations - Repo Updates" --msgbox "Updated system repositories!" 0 0
		fi
		if [ "$option" == 2 ]; then
			dialog  --infobox "Upgrading packages..." 0 0
			xterm -e 'apt -y full-upgrade' &
			dialog --title "Package Operations - Package Upgrades" --msgbox "Upgraded system packages!" 0 0
		fi
		if [ "$option" == 3 ]; then
			dialog  --infobox "Enabling automatic updates..." 0 0
			xterm -e 'apt -y install unattended-upgrades apt-listchanges' &
			dpkg-reconfigure -plow unattended-upgrades
			sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/20auto-upgrades
			dialog --title "Package Operations - Automatic Updates" --msgbox "Enabled automatic updates!" 0 0
		fi 
		if [ "$option" == 4 ]; then
			dialog  --infobox "Removing games and hacking tools..." 0 0
			for i in supertux supertuxkart wesnoth-1.14 0ad extremetuxracer minetest snort xmoto ettercap-graphical flightgear freeciv-client-gtk freeciv-client-sdl openra neverball nsnake gnome-chess gnome-mines gnome-sudoku aisleriot kpat solitaire armagetronad gl-117 hedgewars xblast-tnt chromium-bsu assaultcube trigger-rally pingus njam supertux2 frozen-bubble xboard lincity lincity-ng pioneers scummvm scummvm-tools openmw redeclipse vavoom teeworlds teeworlds-data teeworlds-server freedoom freedoom-freedm freedoom-phase1 freedoom-phase2 freedoom-timidity openarena openarena-server openarena-data openarena-0811 openarena-088 openarena-085-data openarena-085 openarena-0811-maps openttd openttd-data 0ad-data hedgewars-data hedgewars-server hedgewars-dbg berusky berusky2 berusky-data solarwolf nethack-console crawl crawl-tiles crawl-common crawl-data crawl-sdl crawl-console crawl-tiles-data crawl-tiles-sdl crawl-tiles-dbg crawl-dbg wop pingus-data edgar-data pingus-data minecraft-installer jo freedroidrpg boswars ejabberd-contrib phalanx supertuxkart stendhal supertux wireshark* ophcrack aircrack-ng john nmap metasploit-framework burp hydra sqlmap nikto maltego beef-xss cain thc-hydra ettercap-graphical netcat john-data fern-wifi-cracker dsniff hping3; do
				apt -y remove $i
			done
			dialog --title "Package Operations - Hacking Tools & Games" --msgbox "Removed games and hacking tools!" 0 0
		fi
		if [ "$option" == 5 ]; then
			# Get a list of all manually installed packages
			aptlist=$(apt list --installed | grep -F \[installed\] | awk -F'/' '{print $1}')

			# Convert the package list into an array
			package_array=()
			for package in $aptlist; do
				package_array+=($package)
			done

			# Add "off" after each package
			final_package_array=()
			for package in "${package_array[@]}"; do
				final_package_array+=($package "" off)
			done

			# Use dialog to prompt the user
			packages=$(dialog --title "Package Management - Remove Manually Installed Packages" --checklist "Select manually installed packages which should be DELETED (Exercise caution, not every unfamiliar package is dangerous):" 0 0 0 "${final_package_array[@]}" --output-fd 1)
			package_list=""
			for package in $packages; do
				apt -y remove $package
				package_list="$package_list$package\n"
			done
			dialog --title "Package Management - Deleted Packages" --msgbox "$package_list" 0 0
		fi
		if [ "$option" == 6 ]; then
			# Get a list of all held packages
			held=$(apt-mark showhold)

			if [ "$held" == "" ]; then
				dialog --title "Package Management - Unhold Packages" --msgbox "No packages are held" 0 0
			else
				# Convert the package list into an array
				package_array=()
				for package in $held; do
					package_array+=($package)
				done

				# Add "off" after each package
				final_package_array=()
				for package in "${package_array[@]}"; do
					final_package_array+=($package "" off)
				done

				# Use dialog to prompt the user
				packages=$(dialog --title "Package Management - Unhold Packages" --checklist "Select which held packages to unhold:" 0 0 0 "${final_package_array[@]}" --output-fd 1)
				package_list=""
				for package in $packages; do
					apt-mark unhold $package
					package_list="$package_list$package\n"
				done
				dialog --title "Package Management - Unheld Packages" --msgbox "$package_list" 0 0
			fi
		fi
		if [ "$option" == 7 ]; then
			dialog --title "Package Management - Repositories" --msgbox "This will launch stacer, a utility for various system management including repository management, once you are finished, you can close the program to exit." 0 0
			apt -y install stacer >/dev/null
			stacer
		fi
	done
}
firewall_management_menu (){
	firewallm=$(dialog --checklist "Select what firewall operations you want done: " 0 0 0 --output-fd 1 \
		1 "Install UFW and enable" off \
		2 "Open GUI UFW" off \
		3 "List firewall rules" off \
	#  4 "unfilled" off
	)
	# Run commands based on output of dialog
	for option in $firewallm; do
		if [ "$option" == 1 ]; then
			dialog  --infobox "Installing and enabling UFW..." 0 0
			xterm -e 'apt -y install ufw' &
			ufw enable
			dialog --title "Firewall Operations - UFW" --msgbox "Installed and enabled UFW!" 0 0
		fi
		if [ "$option" == 2 ]; then
			apt -y install gufw > /dev/null
			gufw
		fi
		if [ "$option" == 3 ]; then
			dialog --title "Firewall Operations - Open Ports" --msgbox "This requires UFW to be enabled, please ensure it is!" 0 0
			xterm -hold -e 'ufw status verbose' &
			dialog --title "Firewall Operations - Open Ports" --msgbox "Installed and enabled UFW!" 0 0
		fi 
		#if [ "$option" == 4 ]; then

		#fi
	done
}
service_management_menu (){
	servicem=$(dialog --checklist "Select what service operations you want done: " 0 0 0 --output-fd 1 \
		1 "Disable & stop services" off \
		2 "Don't permit root login for SSH Daemon" off \
		3 "Enable & start services" off \
		4 "Manage running processes" off \
		5 "Manage start-up applications" off \
		6 "Don't permit password login for SSH Daemon" off \
		7 "Randomize port used for SSH Daemon" off \
		8 "Enable AppArmor security module" off
		)
	# Run commands based on output of dialog
	for option in $servicem; do
		if [ "$option" == 1 ]; then
			# Get a list of all running services
			services=($(systemctl list-units --type=service --state=active --no-pager --plain | awk '{print $1}'))

			excluded=("${services[@]:1:$((${#services[@]} - 5))}")

			# Add "off" after each output
			final_output_array=()
			for output in "${excluded[@]}"; do
				final_output_array+=($output "" off)
			done
					
			# Use dialog to prompt the user for a list of services to stop
			servicenames=$(dialog --checklist "Select which services should be disabled:" 0 0 0 "${final_output_array[@]}" --output-fd 1)
			service_list=""
			for service in $servicenames; do
				systemctl disable $service >/dev/null
				systemctl stop $service >/dev/null
				service_list="$service_list$service\n"
			done
			dialog --title "Service Operations - Disabled Services" --msgbox "$service_list" 0 0
		fi
		if [ "$option" == 2 ]; then
			dialog  --infobox "Rewriting /etc/ssh/sshd_config..." 0 0
			sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
			systemctl restart sshd.service >/dev/null
			systemctl restart ssh.service >/dev/null
			dialog --title "Service Operations - SSHD Root Login" --msgbox "Root login no longer permitted for SSH Daemon!" 0 0
		fi
		if [ "$option" == 3 ]; then
			services=$(dialog --title "Enable & Start Services" --inputbox "Enter a list of services (comma-separated, no spaces) you want enabled and started:" 0 0 --output-fd 1)
			if [[ -z "${services// }" ]]; then
				dialog --title "Service Operations - Enable & Start Services" --msgbox "No changes were made. Services were not provided." 0 0
			else
				IFS=',' read -ra services_array <<< "$services"

				for service in "${services_array[@]}"; do
					systemctl enable "$service" >/dev/null
					systemctl start "$service" >/dev/null
				done
				add_msg="Services enabled and started: ${services_array[@]}"
				dialog --title "Service Operations - Enable & Start Services" --msgbox "$add_msg" 0 0
			fi
		fi 
		if [ "$option" == 4 ]; then
			dialog --title "Service Operations - Process Manager" --msgbox "This will launch htop, a utility for managing processes, once you are finished, you can press CTRL + C to exit." 0 0
			apt -y install htop >/dev/null
			htop
		fi
		if [ "$option" == 5 ]; then
			dialog --title "Service Operations - Boot-Up Manager" --msgbox "This will launch stacer, a utility for various system management including boot-up applications, once you are finished, you can close the program to exit." 0 0
			apt -y install stacer >/dev/null
			stacer
		fi
		if [ "$option" == 6 ]; then
			echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
			echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
			systemctl restart sshd.service
			systemctl restart ssh.service
			dialog --title "Service Operations - SSHD Password Authentication" --msgbox "Passwords disabled for SSH Daemon! SSH keys must now be used to connect." 0 0
		fi
		if [ "$option" == 7 ]; then
			# Define the valid range of SSH ports
			MIN_PORT=1024
			MAX_PORT=49151

			# Generate a random port within the valid range
			RANDOM_PORT=$(shuf -i $MIN_PORT-$MAX_PORT -n 1)

			# Set the new SSH port in the configuration file
			echo "Port $RANDOM_PORT" >> /etc/ssh/sshd_config

			# Restart the SSH server to apply the new port
			systemctl restart ssh.service
			systemctl restart sshd.service

			dialog --title "Service Operations - SSHD Port Randomization" --msgbox "New SSHD port is $RANDOM_PORT" 0 0
		fi
		if [ "$option" == 8 ]; then
			systemctl enable apparmor.service
			systemctl start apparmor.service
			dialog --title "Service Operations - Enable & Start AppArmor" --msgbox "App Armor is now enabled!" 0 0
		fi
	done
}
malware_management_menu () {
		malwarem=$(dialog --checklist "Select what malware management you want done: " 0 0 0 --output-fd 1 \
		1 "Run ClamAV anti-virus" off \
		2 "Run chkrootkit to find root kits" off \
		3 "Run RKHunter to find root kits" off \
		#4 "unfilled" off
		)
	# Run commands based on output of dialog
	for option in $malwarem; do
		if [ "$option" == 1 ]; then
			apt -y install clamav clamav-daemon
			directory=$(dialog --title "ClamAV Scan" --inputbox "Enter the absolute directory you want to scan:" 0 0 --output-fd 1)
			if [ "$directory" != "" ]; then
				dialog  --title "ClamAV Scan" --infobox "This might take a while - Running malware check on directory '$directory' ..." 0 0
				clamresults=$(clamscan --exclude /proc --exclude /sys --exclude /sysfs --exclude /dev --exclude /run "$directory" --recursive)
				echo "$clamresults" | tee ./clamavresults.txt
				dialog --title "Results of ClamAV malware scan" --msgbox "Output of malware scan sent to clamavresults.txt, which will be located in the directory this script is ran" 0 0
			else
				dialog  --title "ClamAV Scan" --msgbox "No directory specified. No scans made." 0 0
			fi
		fi
		if [ "$option" == 2 ]; then
			apt -y install chkrootkit
			dialog  --infobox "This might take a while - Searching for root kits with CHKRootKit..." 0 0
			chkrootkit | tee ./chkrootkitresults.txt
			dialog --title "Results of CHKRootKit root kit scan" --msgbox "Output of root kit scan sent to chkrootkitresults.txt, which will be located in the directory this script is ran" 0 0
		fi
		if [ "$option" == 3 ]; then
			apt -y install rkhunter
			dialog  --infobox "This might take a while - Searching for root kits with RKHunter ..." 0 0
			rkhunter --check | tee ./rkhunterresults.txt
			echo -e "\nResults of /var/log/rkhunter conveniently appended here!\n"
			cat /var/log/rkhunter.log | tee -a ./rkhunterresults.txt
			dialog --title "Results of RKHunter root kit scan" --msgbox "Output of root kit scan sent to rkhunterresults.txt, which will be located in the directory this script is ran" 0 0
		fi 
		#if [ "$option" == 4 ]; then

		#fi
	done
}
system_management_menu () {
	systemm=$(dialog --checklist "Does general system management fixes:" 0 0 0 --output-fd 1 \
		1 "Configure secure kernel parameters" off \
		2 "Configure sudoers file" off \
		3 "Secure permissions of /etc/passwd and /etc/shadow" off \
		4 "Disable system core dump" off \
		5 "List & disable loaded kernel modules" off \
		6 "Manage system-wide cron jobs" off \
		7 "Set Grub password" off
		)
	# Run commands based on output of dialog
	for option in $systemm; do
		if [ "$option" == 1 ]; then
			curl -o /etc/sysctl.d/99-custom.conf https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf
			dialog  --title "System Management - Kernel Security Measures" --msgbox "Implemented various kernel tweaks!" 0 0
			sysctl -p /etc/sysctl.d/99-custom.conf
		fi
		if [ "$option" == 2 ]; then
			dialog  --title "System Management - Sudoers File Config" --msgbox "This will launch visudo using the nano editor, press CTRL + X to exit, and choose whether to save or not. Beware, what you do here can break the system!" 0 0
			EDITOR=/usr/bin/nano visudo
		fi
		if [ "$option" == 3 ]; then
			chmod 644 /etc/passwd
			chmod 640 /etc/shadow
			dialog  --title "System Management - Permissions Config" --msgbox "Changed /etc/passwd to use 644 permissions and /etc/shadow to use 640 permissions" 0 0
		fi
		if [ "$option" == 4 ]; then
			echo '* hard core 0' >> /etc/security/limits.conf
			echo '* soft core 0' >> /etc/security/limits.conf
			touch /etc/sysctl.d/9999-disable-core-dump.conf
			echo "fs.suid_dumpable=0" >> /etc/sysctl.d/9999-disable-core-dump.conf
			echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.d/9999-disable-core-dump.conf
			sysctl -p /etc/sysctl.d/9999-disable-core-dump.conf
		fi
		if [ "$option" == 5 ]; then
			# Get a list of all loaded modules
			modules=$(lsmod | awk '{print $1}' | tail -n +2)

			# Convert into array
			module_array=()
			for module in $modules; do
				module_array+=($module)
			done

			# Add "off" after each output
			final_output_array=()
			for output in "${module_array[@]}"; do
				final_output_array+=($output "" off)
			done
					
			# Use dialog to prompt the user for a list of services to stop
			modulenames=$(dialog --checklist "Select which modules should be disabled:" 0 0 0 "${final_output_array[@]}" --output-fd 1)
			module_list=""
			for module in $modulenames; do
				echo -e "$module\n" | tee -a /etc/modprobe.d/blacklist.conf
				module_list="$module_list$module\n"
			done
			dialog --title "These modules have been disabled: " --msgbox "$module_list" 0 0
		fi
		if [ "$option" == 6 ]; then
			files=()
			while IFS= read -r -d '' file; do
    		files+=("$file")
			done < <(find /etc -type f -name "*cron*" -print0)

			options=()
			for i in "${!files[@]}"; do
				options+=($((i + 1)) "${files[i]}")
			done

			cronfiles=$(dialog --title "System Management - Edit Cron Jobs" --menu "Found these cron files in /etc - Select which file should be edited:" 0 0 0 --output-fd 1 "${options[@]}")
			dialog --title "System Management - Edit Cron Jobs" --msgbox "This will launch the nano editor, press CTRL + X to exit, and choose whether to save or not." 0 0
			selected_file_index=$((cronfiles - 1))
			nano "${files[$selected_file_index]}"
		fi
		if [ "$option" == 7 ]; then
			dialog --title "System Management - Grub Password" --msgbox "What you are doing here can lock you out of your system if you reboot, remember the password!" 0 0
			grubpwd=$(dialog --title "System Management - Grub Password" --inputbox "Enter the password you want to use for Grub, do NOT forget this:" 0 0 --output-fd 1)
			hash=$(echo -e "$grubpwd\n$grubpwd" | LC_ALL=C /usr/bin/grub-mkpasswd-pbkdf2 | awk '/hash of / {print $NF}')
			echo -e "\nset superusers=$(logname)" >> /etc/grub.d/40_custom
			echo "password_pbkdf2 $(logname) $hash" >> /etc/grub.d/40_custom
			update-grub
			dialog --title "System Management - Grub Password" --msgbox "Your Grub password is: $grubpwd" 0 0
		fi
	done
}
misc_management_menu () {
	infom=$(dialog --checklist "Various micellaneous options that doesn't fit with any of the other categories, or sometimes may not help gain points: " 0 0 0 --output-fd 1 \
		1 "List and clear immutable attributes of files/directories" off \
		2 "List and remove potential unauthorized files in /home" off \
		3 "Edit files in /etc/grub.d/ to find malicious options" off \
		4 "List files with a SUID or GUID permission value set to it and clear them" off \
		5 "List contents of /etc/hosts file to find potentially harmful DNS redirects" off \
		6 "Edit files in /etc/skel to find malicious entries" off \
		7 "Find symbolic links in /bin and /sbin, with the option to unlink" off
		)
	for option in $infom; do
		if [ "$option" == 1 ]; then
			dialog  --infobox "Searching / directory for files with immutable attributes..." 0 0
			readarray -t attrLines < <(lsattr -laR / 2>/dev/null | grep "Immutable" | sed 's/ Immutable//g')
			if [ ${#attrLines[@]} -eq 0 ]; then
				dialog --title "Misc - Files With Attributes" --msgbox "No files with attributes found" 0 0
			else
				# Convert into array
				dialogArray=()
				for line in "${attrLines[@]}"; do
					dialogArray+=("$line" "" off)
				done

				# Use dialog to prompt the user for a list of files to remove attributes
				filenames=$(dialog --separate-output --title "Misc - Remove Attributes" --checklist "Select files from which to remove the file attributes:" 0 0 0 "${dialogArray[@]}" --output-fd 1)
				OLDIFS=$IFS
				IFS=$'\n'
				file_list=""
				for entry in $filenames; do
					echo "$entry"
					chattr -i "$entry"
					file_list+="$entry\n"
				done
				IFS=$OLDIFS
				dialog --title "Misc - Removed Attributes From These Files" --msgbox "$file_list" 0 0
			fi
		fi
		if [ "$option" == 2 ]; then
			dialog  --infobox "Searching /home directories for potentially unauthorized files..." 0 0
			readarray -t filels < <(find /home -type f \( -name "*.wav" -o -name "*.mp3" -o -name "*.png" -o -name "*.mp4" -o -name "*.mkv" -o -name "*.webm" -o -name "*.webp" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" -o -name "*.avi" -o -name "*.flv" -o -name "*.mov" -o -name "*.wmv" -o -name "*.m4v" \))
			if [ ${#filels[@]} -eq 0 ]; then
				dialog --title "Misc - Unauthorized Files" --msgbox "No unauthorized files found" 0 0
			else
				# Convert the file list into an array
				file_array=()
				for file in "${filels[@]}"; do
					file_array+=("$file" "" off)
				done

				# Use dialog to prompt the user for a list of files to delete
				filelocations=$(dialog --separate-output --title "Misc - Delete Files" --checklist "Found these potentially unauthorized files - Select which files should be deleted:" 0 0 0 "${file_array[@]}" --output-fd 1)
				OLDIFS=$IFS
				IFS=$'\n'
				file_list=""
				for file in $filelocations; do
					rm -f "$file" >/dev/null
					file_list="$file_list$file\n"
				done
				IFS=$OLDIFS
				dialog --title "User Management - Deleted files" --msgbox "$file_list" 0 0
			fi
		fi
		if [ "$option" == 3 ]; then
			shopt -s extglob
			shopt -s dotglob
			files=()
			i=0
			for file in /etc/grub.d/*; do
				files+=("$file")
				((i++))
			done

			options=()
			for i in "${!files[@]}"; do
				options+=($((i + 1)) "${files[i]}")
			done

			grubfiles=$(dialog --title "Misc - Edit /etc/grub.d" --menu "Found these files in /etc/grub.d - Select which file should be edited:" 0 0 0 --output-fd 1 "${options[@]}")
			dialog --title "Misc - Edit /etc/grub.d" --msgbox "This will launch the nano editor, press CTRL + X to exit, and choose whether to save or not." 0 0
			selected_file_index=$((grubfiles - 1))
			nano "${files[$selected_file_index]}"
			update-grub
		fi
		if [ "$option" == 4 ]; then
			dialog  --infobox "Searching / directory for files with a SUID/GUID bit..." 0 0
			readarray -t suidguid < <(find / -type f \( -perm /4000 -o -perm /2000 \) -exec stat -c "%A %U %n" {} \; | awk '{print $3}')

			if [ ${#suidguid[@]} -eq 0 ]; then
				dialog --title "Misc - SUID/GUID Permissions" --msgbox "No files found with a SUID/GUID Permission" 0 0
			else
				# Convert the file list into an array
				file_array=()
				for file in "${suidguid[@]}"; do
					file_array+=("$file" "" off)
				done

				# Use dialog to prompt the user for a list of files TO DELETE!!!
				suguidinput=$(dialog --separate-output --title "Misc - SUID/GUID Permissions" --checklist "Found these files with a SUID/GUID Permission - Select which files should be cleared of these:" 0 0 0 "${file_array[@]}" --output-fd 1)
				suguid_list=""
				OLDIFS=$IFS
				IFS=$'\n'
				for perm in $suguidinput; do
					chmod u-s,g-s "$perm" >/dev/null
					suguid_list="$suguid_list$perm\n"
				done
				IFS=$OLDIFS
				dialog --title "Misc - Removed SUID/GUID Permissions" --msgbox "$suguid_list" 0 0
			fi
		fi
		if [ "$option" == 5 ]; then
			dialog --title "Misc - List Contents of /etc/hosts" --msgbox "This will launch the nano editor, press CTRL + X to exit, and choose whether to save or not." 0 0
			nano /etc/hosts
		fi
		if [ "$option" == 6 ]; then
			shopt -s extglob
			shopt -s dotglob
			files=()
			i=0
			for file in /etc/skel/*; do
				files+=("$file")
				((i++))
			done

			options=()
			for i in "${!files[@]}"; do
				options+=($((i + 1)) "${files[i]}")
			done

			skelfiles=$(dialog --title "Misc - Edit /etc/skel" --menu "Found these files in /etc/skel - Select which file should be edited:" 0 0 0 --output-fd 1 "${options[@]}")
			dialog --title "Misc - Edit /etc/skel" --msgbox "This will launch the nano editor, press CTRL + X to exit, and choose whether to save or not." 0 0
			selected_file_index=$((skelfiles - 1))
			nano "${files[$selected_file_index]}"
		fi
		if [ "$option" == 7 ]; then
			readarray -t links < <(find /sbin/* /bin/* /usr/bin/* -type l)
			if [ ${#links[@]} -eq 0 ]; then
				dialog --title "Misc - Find Symbolic Links" --msgbox "No symbolic links found" 0 0
			else
				file_array=()
				for file in "${links[@]}"; do
					file_array+=("$file" "" off)
				done

				symbolicinput=$(dialog --separate-output --title "Misc - Find Symbolic Links" --checklist "Found these symbolic links - Select which files should be unlinked:" 0 0 0 "${file_array[@]}" --output-fd 1)
				symbolic_list=""
				OLDIFS=$IFS
				IFS=$'\n'
				for file in $symbolicinput; do
					unlink "$file" >/dev/null
					symbolic_list="$symbolic_list$file\n"
				done
				IFS=$OLDIFS
				dialog --title "Misc - Removed Symbolic Links" --msgbox "$symbolic_list" 0 0
			fi
		fi
	done
}

while true; do      
	mainmenu=$(dialog --menu "Choose a category: " 0 0 0 --output-fd 1 \
		1 "User Management" \
		2 "Package Management & Updates" \
		3 "Firewall" \
		4 "Service Management" \
		5 "Malware Checks" \
		6 "System Management" \
		7 "Miscellaneous" \
		8 "Finished (Close Prompt)"
	)
	if [ $? -ne 0 ]; then
				clear && break
	fi
	case $mainmenu in
		1) user_management_menu ;;
		2) package_management_menu ;;
		3) firewall_management_menu ;;
		4) service_management_menu ;;
		5) malware_management_menu ;;
		6) system_management_menu ;;
		7) misc_management_menu ;;
		8) clear && exit 0 ;;
	esac
done
