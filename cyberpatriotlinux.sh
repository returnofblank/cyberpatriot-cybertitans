#!/bin/bash

REQUIRED_PKG="dialog"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG | grep "install ok installed")

echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "No $REQUIRED_PKG installed. This is required to use the TUI included with this script. You will be asked to input your password to install $REQUIRED_PKG. Also, this will give the script the required privileges for certain processes."
  sudo apt -y install $REQUIRED_PKG
fi

if [[ $? -ne 0 ]]; then
  echo "This script is running without root privileges, which is not possible. Exiting"
  exit 0
fi

dialog --msgbox "This is not a comprehensive utility; many operations will still have to be done manually!" 0 0

while true; do
  # Functions for display management options
  user_management_menu() {
    userm=$(dialog --checklist "Select what user management you want done: " 0 0 0 --output-fd 1 \
      1 "Replace passwords of administrators" off \
      2 "Remove unauthorized users from sudo and add users supposed to be in sudo" off \
      3 "Remove unauthorized users" off \
      4 "Disable root login" off
    )
    # Run commands based on output of dialog
    for option in $userm; do
      if [ "$option" == 1 ]; then
        sudo_users=$(getent group sudo | cut -d : -f 4)
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
            echo "$users":"$password" | sudo chpasswd

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
          current_sudo_users=($(getent group sudo | cut -d ':' -f 4 | tr ',' ' '))

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
            usermod -aG sudo "$user"
          done

          # Remove users from the sudo group
          for user in "${users_to_remove[@]}"; do
            deluser "$user" sudo
          done

          # Display the changes made using dialog
          add_msg="Users added to sudo group: ${users_to_add[*]}"
          remove_msg="Users removed from sudo group: ${users_to_remove[*]}"

          dialog --infobox "$add_msg\n$remove_msg" 0 0
        fi
      fi
      if [ "$option" == 3 ]; then
        # Get a list of real users on the system
          users=$(awk -F: '$3 >= 1000 && $1 != "'"$(logname)"'" && $1 != "nobody" { print $1 }' /etc/passwd)

        # Convert the user list into an array
        user_array=()
        for user in $users; do
            user_array+=($user "" off)
        done

        # Use dialog to prompt the user for a list of usernames TO DELETE!!!
        usernames=$(dialog --checklist "Select usernames who should be DELETED (Refer to readme to compare):" 0 0 0 "${user_array[@]}" --output-fd 1)
        user_list=""
        for user in $usernames; do
          deluser "$user"
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
    5) clear && exit 0 ;;
  esac
done

