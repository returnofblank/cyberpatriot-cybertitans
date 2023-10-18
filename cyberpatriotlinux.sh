#!/bin/bash

# Package name to check
PACKAGE_NAME="dialog"

# Check if the package is installed
dpkg --get-selections | grep -q $PACKAGE_NAME > /dev/null
if [[ $? -ne 0 ]]; then
  echo "The package $PACKAGE_NAME is not installed."
  sudo apt -y install $PACKAGE_NAME
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "This script is running without root privileges, which is not possible. Exiting"
  exit 0
fi

dialog --msgbox "This is not a comprehensive utility; many operations will still have to be done manually!" 0 0

while true; do
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
      
  # Functions for display management options
  user_management_menu() {
    userm=$(dialog --checklist "Select what user management you want done: " 0 0 0 --output-fd 1 \
      1 "Replace passwords of administrators" off \
      2 "Remove unauthorized users from sudo and add users supposed to be in sudo" off \
      3 "Remove unauthorized users" off \
      4 "Disable root login" off \
      5 "Enable password policy practices" off \
      6 "Disable guest account, if present" off
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
        sed -i "/^root:/s:/bin/bash:/sbin/nologin:g" /etc/passwd
        dialog --title "User Management - Root Disabled" --msgbox "Login no longer enabled for Root user" 0 0
      fi
      if [ "$option" == 5 ]; then
        echo -e "minlen = 14\nucredit = -1\nlcredit = -1\nocredit = -1\ndcredit = -1" >> /etc/security/pwquality.conf
        sed -i '/pam_unix.so/ s/$/ remember=5 minlen=14/' /etc/pam.d/common-password
        sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
        sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs
        sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
        # echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth #Pretty sure this borks the system
        dialog --title "User Management - Password Policy" --msgbox "All passwords require 14 characters and require uppercase, lowercase, digits, and special characters" 0 0
      fi
      if [ "$option" == 6 ]; then
        echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
        dialog --title "User Management - Guest Account" --msgbox "Guest account disabled, if present" 0 0
      fi
    done
  }
  package_management_menu (){
    packagem=$(dialog --checklist "Select what package operations you want done: " 0 0 0 --output-fd 1 \
      1 "Update system repositories" off \
      2 "Upgrade system packages" off \
      3 "Enable automatic updates" off \
      4 "Remove potential hacking tools and games" off \
      5 "Remove manually installed packages" off
      )
    # Run commands based on output of dialog
    for option in $packagem; do
      if [ "$option" == 1 ]; then
        dialog --title "Package Operations" --infobox "Updating system repositories" 0 0
        apt update
        dialog --title "Package Operations - Repo Updates" --msgbox "Updated system repositories!" 0 0
      fi
      if [ "$option" == 2 ]; then
        dialog  --infobox "Upgrading packages..." 0 0
        apt -y upgrade
        dialog --title "Package Operations - Package Upgrades" --msgbox "Upgraded system packages!" 0 0
      fi
      if [ "$option" == 3 ]; then
        dialog  --infobox "Enabling automatic updates..." 0 0
        apt -y install unattended-upgrades apt-listchanges
        dpkg-reconfigure -plow unattended-upgrades
        sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/20auto-upgrades
        dialog --title "Package Operations - Automatic Updates" --msgbox "Enabled automatic updates!" 0 0
      fi 
      if [ "$option" == 4 ]; then
        dialog  --infobox "Removing games and hacking tools..." 0 0
        for i in supertux supertuxkart wesnoth-1.14 0ad extremetuxracer xmoto ettercap-graphical flightgear freeciv-client-gtk freeciv-client-sdl openra neverball nsnake gnome-chess gnome-mines gnome-sudoku aisleriot kpat solitaire armagetronad gl-117 hedgewars xblast-tnt chromium-bsu assaultcube trigger-rally pingus njam supertux2 frozen-bubble xboard lincity lincity-ng pioneers scummvm scummvm-tools openmw redeclipse vavoom teeworlds teeworlds-data teeworlds-server freedoom freedoom-freedm freedoom-phase1 freedoom-phase2 freedoom-timidity openarena openarena-server openarena-data openarena-0811 openarena-088 openarena-085-data openarena-085 openarena-0811-maps openttd openttd-data 0ad-data hedgewars-data hedgewars-server hedgewars-dbg berusky berusky2 berusky-data solarwolf nethack-console crawl crawl-tiles crawl-common crawl-data crawl-sdl crawl-console crawl-tiles-data crawl-tiles-sdl crawl-tiles-dbg crawl-dbg wop pingus-data edgar-data pingus-data minecraft-installer jo freedroidrpg boswars ejabberd-contrib phalanx supertuxkart stendhal supertux wireshark* ophcrack aircrack-ng john nmap metasploit-framework burp hydra sqlmap nikto maltego beef-xss cain thc-hydra ettercap-graphical netcat john-data fern-wifi-cracker dsniff hping3; do
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

        # Use dialog to prompt the user for a list of usernames TO DELETE!!!
        packages=$(dialog --title "Package Management - Remove Manually Installed Packages" --checklist "Select manually installed packages which should be DELETED (Exercise caution, not every unfamiliar package is dangerous):" 0 0 0 "${final_package_array[@]}" --output-fd 1)
        package_list=""
        for package in $packages; do
          apt -y remove $package
          package_list="$package_list$package\n"
        done
        dialog --title "Package Management - Deleted Packages" --msgbox "$package_list" 0 0
      fi
    done
  }
  firewall_management_menu (){
    firewallm=$(dialog --checklist "Select what firewall operations you want done: " 0 0 0 --output-fd 1 \
      1 "Install UFW and enable" off \
    #  2 "unfilled" off \
    #  3 "unfilled" off \
    #  4 "unfilled" off
    )
    # Run commands based on output of dialog
    for option in $firewallm; do
      if [ "$option" == 1 ]; then
        dialog  --infobox "Installing and enabling UFW..." 0 0
        apt -y install ufw
        ufw enable
        dialog --title "Firewall Operations - UFW" --msgbox "Installed and enabled UFW!" 0 0
      fi
      #if [ "$option" == 2 ]; then

      #fi
      #if [ "$option" == 3 ]; then

      #fi 
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
      5 "Manage start-up applications" off
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
        systemctl restart sshd.service
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
    done
      if [ "$option" == 3 ]; then
        dialog --title "Service Operations - Boot-Up Manager" --msgbox "This will launch bum, a utility for managing boot-up applications, once you are finished, you can close the program to exit." 0 0
        apt -y install bum
        bum
      fi
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
        dialog  --infobox "This might take a while - Running malware check on directory '$directory' ..." 0 0
        clamresults=$(clamscan --exclude /proc --exclude /sys --exclude /sysfs --exclude /dev --exclude /run "$directory" --recursive)
        echo "$clamresults" | tee ./clamavresults.txt
        dialog --title "Results of ClamAV malware scan" --msgbox "Output of malware scan sent to clamavresults.txt, which will be located in the directory this script is ran" 0 0
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
        cat /var/log/rkhunter >> ./rkhunterresults.txt
        dialog --title "Results of RKHunter root kit scan" --msgbox "Output of root kit scan sent to rkhunterresults.txt, which will be located in the directory this script is ran" 0 0
      fi 
      #if [ "$option" == 4 ]; then

      #fi
    done
  }
  information_management_menu () {
    infom=$(dialog --checklist "This compiles various information about the system to assist in manual interventions. This is usually items that can't be automated or isn't safe to do so: " 0 0 0 --output-fd 1 \
      1 "List all files/directories with an attribute" off \
      #2 "unfilled" off \
      #3 "unfilled" off \
      #4 "unfilled" off
      )
    for option in $infom; do
      if [ "$option" == 1 ]; then
        dialog  --infobox "Searching /etc and /home directories for files with attributes..." 0 0
        attributels=$(find /home /etc -type f -exec lsattr {} \; | grep -v -e "--------------e-------" | grep -v -e "----------------------")
        dialog --title "Files with attributes in /etc or /home" --msgbox "$attributels" 0 0
      fi
      #if [ "$option" == 2 ]; then

      #fi
      #if [ "$option" == 3 ]; then

      #fi
      #if [ "$option" == 4 ]; then

      #fi
    done
  }
  mainmenu=$(dialog --menu "Choose a category: " 0 0 0 --output-fd 1 \
    1 "User Management" \
    2 "Package Management & Updates" \
    3 "Firewall" \
    4 "Service Management" \
    5 "Malware Checks" \
    6 "Information" \
    7 "Finished (Close Prompt)"
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
    6) information_management_menu ;;
    7) clear && exit 0 ;;
  esac
done