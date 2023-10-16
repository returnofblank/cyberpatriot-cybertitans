#!/bin/bash

#Installs dialog on any system
package_installed() {
  local package="$1"
  if command -v "$package" &>/dev/null; then
    return 0
  else
    return 1
  fi
}

# Function to install a package using the detected package manager
install_package() {
  local package_manager="$1"
  local package_name="$2"

  case "$package_manager" in
    apt)
      sudo apt-get update
      sudo apt-get install -y "$package_name"
      ;;
    yum)
      sudo yum install -y "$package_name"
      ;;
    *)
      echo "Unsupported package manager. Please install '$package_name' manually."
      exit 1
      ;;
  esac
}

# Detect the package manager
if package_installed "apt"; then
  package_manager="apt"
elif package_installed "yum"; then
  package_manager="yum"
else
  echo "Unsupported package manager. Please install 'dialog' manually."
  exit 1
fi

package_name="dialog"

# Check if 'dialog' is installed, and if not, install it
if ! package_installed "$package_name"; then
  echo "Package '$package_name' is not installed. Attempting to install..."
  install_package "$package_manager" "$package_name"
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
      4 "Disable root login" off)
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
        usernames=$(dialog --inputbox "Enter a list of usernames (comma-separated) who should be in the sudo group:" 0 0 --output-fd 1)
        # Removes white spaces
        usernames=$(echo "$usernames" | tr -s ' ')
        if [[ -z "${usernames// }" ]]; then
          dialog --msgbox "No changes were made. Usernames were not provided." 0 0
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
            usermod -aG "$group_name" "$user" &>/dev/null
          done

          # Remove users from the sudo group
          for user in "${users_to_remove[@]}"; do
              deluser "$user" "$group_name" &>/dev/null
          done

          # Display the changes made using dialog
          add_msg="Users added to sudo group: ${users_to_add[*]}"
          remove_msg="Users removed from sudo group: ${users_to_remove[*]}"
          dialog --msgbox "$add_msg\n$remove_msg" 0 0
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
        usernames=$(dialog --checklist "Select usernames who should be DELETED (Refer to readme to compare):" 0 0 0 "${final_user_array[@]}" --output-fd 1)
        user_list=""
        for user in $usernames; do
          deluser "$user" &>/dev/null
          user_list="$user_list$user\n"
        done
        dialog --title "Deleted users" --msgbox "$user_list" 0 0
      fi
      if [ "$option" == 4 ]; then
        sed -i "/^root:/s:/bin/bash:/sbin/nologin:g" /etc/passwd
        dialog --title "Root Disabled" --msgbox "Login no longer enabled for Root user" 0 0
      fi
    done
  }
  package_management_menu (){
    packagem=$(dialog --checklist "Select what package management you want done: " 0 0 0 --output-fd 1 \
      1 "Update system repositories" off \
      2 "Upgrade system packages" off \
      3 "Enable automatic updates" off \
      4 "Remove potential hacking tools and games" off)
    # Run commands based on output of dialog
    for option in $packagem; do
      if [ "$option" == 1 ]; then
        dialog  --infobox "Updating system repositories" 0 0
        apt update 2>/dev/null
        dnf upgrade --refresh 2>/dev/null
        zypper ref 2>/dev/null
        dialog --title "Updated system repositories" --msgbox "Updated system repositories!" 0 0
      fi
      if [ "$option" == 2 ]; then
        dialog  --infobox "Upgrading packages..." 0 0
        apt -y upgrade 2>/dev/null
        dnf upgrade -y 2>/dev/null
        zypper up -y 2>/dev/null
        dialog --title "Upgraded system packages" --msgbox "Upgraded system packages!" 0 0
      fi
      if [ "$option" == 3 ]; then
        dialog  --infobox "Enabling automatic updates..." 0 0
        apt -y install unattended-upgrades apt-listchanges 2>/dev/null
        dpkg-reconfigure -plow unattended-upgrades 2>/dev/null
        sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/20auto-upgrades
        systemctl enable --now dnf-automatic.timer 2>/dev/null
        zypper install yast2-online-update-configuration 2>/dev/null
        yast2 online_update_configuration 2>/dev/null
        dialog --title "Enabled automatic updates" --msgbox "Enabled automatic updates!" 0 0
      fi 
      if [ "$option" == 4 ]; then
        dialog  --infobox "Removing games and hacking tools..." 0 0
        for i in supertux supertuxkart wesnoth-1.14 0ad extremetuxracer xmoto ettercap-graphical flightgear freeciv-client-gtk freeciv-client-sdl openra neverball nsnake gnome-chess gnome-mines gnome-sudoku aisleriot kpat solitaire armagetronad gl-117 hedgewars xblast-tnt chromium-bsu assaultcube trigger-rally pingus njam supertux2 frozen-bubble xboard lincity lincity-ng pioneers scummvm scummvm-tools openmw redeclipse vavoom teeworlds teeworlds-data teeworlds-server freedoom freedoom-freedm freedoom-phase1 freedoom-phase2 freedoom-timidity openarena openarena-server openarena-data openarena-0811 openarena-088 openarena-085-data openarena-085 openarena-0811-maps openttd openttd-data 0ad-data hedgewars-data hedgewars-server hedgewars-dbg berusky berusky2 berusky-data solarwolf nethack-console crawl crawl-tiles crawl-common crawl-data crawl-sdl crawl-console crawl-tiles-data crawl-tiles-sdl crawl-tiles-dbg crawl-dbg wop pingus-data edgar-data pingus-data minecraft-installer jo freedroidrpg boswars ejabberd-contrib phalanx supertuxkart stendhal supertux wireshark* ophcrack aircrack-ng john nmap metasploit-framework burp hydra sqlmap nikto maltego beef-xss cain thc-hydra ettercap-graphical netcat john-data fern-wifi-cracker dsniff hping3; do
          apt -y remove $i 2>/dev/null
          dnf remove $i -y 2>/dev/null
          zypper rm $i -y 2>/dev/null
        done
        dialog --title "Removed games and hacking tools" --msgbox "Removed games and hacking tools!" 0 0
      fi
    done
  }
  firewall_management_menu (){
    firewallm=$(dialog --checklist "Select what firewall management you want done: " 0 0 0 --output-fd 1 \
      1 "Install UFW and enable" off \
      2 "unfilled" off \
      3 "unfilled" off \
      4 "unfilled" off)
    # Run commands based on output of dialog
    for option in $firewallm; do
      if [ "$option" == 1 ]; then
        dialog  --infobox "Installing and enabling UFW..." 0 0
        apt -y install ufw 2>/dev/null
        dnf install ufw -y 2>/dev/null
        zypper in $i -y 2>/dev/null
        ufw enable
        dialog --title "Installed and enabled UFW" --msgbox "Installed and enabled UFW!" 0 0
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
    servicem=$(dialog --checklist "Select what service management you want done: " 0 0 0 --output-fd 1 \
      1 "List and disable services" off \
      2 "Don't permit root login for SSH Daemon" off \
      3 "unfilled" off \
      4 "unfilled" off)
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
          systemctl disable $service &>/dev/null
          systemctl stop $service &>/dev/null
          service_list="$service_list$service\n"
        done
        dialog --title "Disabled services" --msgbox "$service_list" 0 0
      fi
      if [ "$option" == 2 ]; then
        dialog  --infobox "Rewriting /etc/ssh/sshd_config..." 0 0
        sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
        systemctl restart sshd.service
        dialog --title "Root login no longer permitted for SSH Daemon" --msgbox "Root login no longer permitted for SSH Daemon!" 0 0
      fi
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
    5 "Finished (Close Prompt)"
  )
  if [ $? -ne 0 ]; then
        clear && break
  fi
  case $mainmenu in
    1) user_management_menu ;;
    2) package_management_menu ;;
    3) firewall_management_menu ;;
    4) service_management_menu ;;
    5) clear && exit 0 ;;
  esac
done

