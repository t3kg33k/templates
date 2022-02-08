#!/bin/bash

#### SETTING UP AIDE ####
#
#echo "*** INSTALL AIDE ***"
#
#sleep 2
#function package_command {

# Load function arguments into local variables
#local package_operation=$1
#local package=$2

# Check sanity of the input
#if [ $# -ne "2" ]
#then
#  echo "Usage: package_command 'install/uninstall' 'rpm_package_name"
#  echo "Aborting."
#  exit 1
#fi
# If dnf is installed, use dnf; otherwise, use yum
#if [ -f "/usr/bin/dnf" ] ; then
#  install_util="/usr/bin/dnf"
#else
#  install_util="/usr/bin/yum"
#fi
#if [ "$package_operation" != 'remove' ] ; then
  # If the rpm is not installed, install the rpm
#  if ! /bin/rpm -q --quiet $package; then
#    $install_util -y $package_operation $package
#  fi
#else
  # If the rpm is installed, uninstall the rpm
#  if /bin/rpm -q --quiet $package; then
#    $install_util -y $package_operation $package
#  fi
#fi

#}

#package_command install aide
#sleep 2
#echo
#echo "*** GENERATING A NEW DATABASE ***"
#aide --init
#echo
#echo "*** COPYING THE NEW DATABASE TO THE DEFAULT LOCATION ***"
#cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
#echo
#echo "*** CHECK THE DATABASE ***"
#aide --check
#sleep 2
#echo *** Setting update daily execution schedule ***
#echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
#sleep 2
#

#### ACCOUNT AND ACCESS CONTROL ####
#
echo "*** PREVENT LOG IN WITH EMPTY PASSWORD ***"
/usr/bin/sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth
sleep 2
#
echo "*** SETTING PASSWORD MAX AGE ***"
var_accounts_maximum_age_login_defs="90"

grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  /usr/bin/sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi
sleep 2
#
echo "*** SET ACCOUNT EXPIRATION FOLLOWING INACTIVITY ***"
var_account_disable_post_pw_expiration="90"

grep -q ^INACTIVE /etc/default/useradd && \
  /usr/bin/sed -i "s/INACTIVE.*/INACTIVE=$var_account_disable_post_pw_expiration/g" /etc/default/useradd
if ! [ $? -eq 0 ]; then
    echo "INACTIVE=$var_account_disable_post_pw_expiration" >> /etc/default/useradd
fi
sleep 2
#
echo "*** SET PASSWORD STRENGTH MIN DIGITAL CHARACTERS ***"
var_password_pam_dcredit="-1"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal CCENUM.
  # If CCENUM exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != 'CCENUM' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=${key//[!a-zA-Z]/}

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" $stripped_key $value
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    echo -ne "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -ne "\n$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/security/pwquality.conf' '^dcredit' $var_password_pam_dcredit 'CCE-27214-6' '%s = %s'
sleep 2
#
echo "*** SET PASSWORD MIN LENGTH ***"
var_password_pam_minlen="7"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal CCENUM.
  # If CCENUM exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != 'CCENUM' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=${key//[!a-zA-Z]/}

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" $stripped_key $value
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    echo -ne "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -ne "\n$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/security/pwquality.conf' '^minlen' $var_password_pam_minlen 'CCE-27293-0' '%s = %s'
sleep 2
#
echo "*** SET PASSWORD STRENGTH MIN UPPERCASE CHARACTERS ***"
var_password_pam_ucredit="-1"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal CCENUM.
  # If CCENUM exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != 'CCENUM' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=${key//[!a-zA-Z]/}

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" $stripped_key $value
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    echo -ne "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -ne "\n$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/security/pwquality.conf' '^ucredit' $var_password_pam_ucredit 'CCE-27200-5' '%s = %s'
sleep 2
#
echo "*** SET PASSWORD STRENGTH MIN LOWERCASE CHARACTERS ***"
var_password_pam_lcredit="-1"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal CCENUM.
  # If CCENUM exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != 'CCENUM' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=${key//[!a-zA-Z]/}

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" $stripped_key $value
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    echo -ne "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -ne "\n$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/security/pwquality.conf' '^lcredit' $var_password_pam_lcredit 'CCE-27345-8' '%s = %s'
sleep 2
#
echo "*** SET DENY FOR FAILED PASSWORD ATTEMPTS ***"
var_accounts_passwords_pam_faillock_deny="6"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do

	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, deny directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*deny=" $pamFile; then

			# both pam_faillock.so & deny present, just correct deny directive value
			/usr/bin/sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile
			/usr/bin/sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile

		# pam_faillock.so present, but deny directive not yet
		else

			# append correct deny value to appropriate places
			/usr/bin/sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
			/usr/bin/sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'deny' option
		/usr/bin/sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
		/usr/bin/sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
		/usr/bin/sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done
sleep 2
#
echo "*** SET LOCKOUT TIME FOR FAILED PASSWORD ATTEMPTS ***"
var_accounts_passwords_pam_faillock_unlock_time="1800"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do

	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, unlock_time directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*unlock_time=" $pamFile; then

			# both pam_faillock.so & unlock_time present, just correct unlock_time directive value
			/usr/bin/sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			/usr/bin/sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile

		# pam_faillock.so present, but unlock_time directive not yet
		else

			# append correct unlock_time value to appropriate places
			/usr/bin/sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			/usr/bin/sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'unlock_time' option
		/usr/bin/sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		/usr/bin/sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		/usr/bin/sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done
sleep 2
#
echo "*** LIMIT PASSWORD REUSE ***"
var_password_pam_unix_remember="4"

if grep -q "remember=" /etc/pam.d/system-auth; then
	/usr/bin/sed -i --follow-symlinks "s/\(^password.*sufficient.*pam_unix.so.*\)\(\(remember *= *\)[^ $]*\)/\1remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
else
	/usr/bin/sed -i --follow-symlinks "/^password[[:space:]]\+sufficient[[:space:]]\+pam_unix.so/ s/$/ remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
fi
sleep 2
#
echo "*** ENABLE SMART CARD LOGIN ***"
# Install required packages

function package_command {

# Load function arguments into local variables
local package_operation=$1
local package=$2

# Check sanity of the input
if [ $# -ne "2" ]
then
  echo "Usage: package_command 'install/uninstall' 'rpm_package_name"
  echo "Aborting."
  exit 1
fi

# If dnf is installed, use dnf; otherwise, use yum
if [ -f "/usr/bin/dnf" ] ; then
  install_util="/usr/bin/dnf"
else
  install_util="/usr/bin/yum"
fi

if [ "$package_operation" != 'remove' ] ; then
  # If the rpm is not installed, install the rpm
  if ! /bin/rpm -q --quiet $package; then
    $install_util -y $package_operation $package
  fi
else
  # If the rpm is installed, uninstall the rpm
  if /bin/rpm -q --quiet $package; then
    $install_util -y $package_operation $package
  fi
fi

}

package_command install esc
package_command install pam_pkcs11

# Enable pcscd.socket systemd activation socket

function service_command {

# Load function arguments into local variables
local service_state=$1
local service=$2
local xinetd=$(echo $3 | /usr/bin/cut -d'=' -f2)

# Check sanity of the input
if [ $# -lt "2" ]
then
  echo "Usage: service_command 'enable/disable' 'service_name.service'"
  echo
  echo "To enable or disable xinetd services add \'xinetd=service_name\'"
  echo "as the last argument"
  echo "Aborting."
  exit 1
fi

# If systemctl is installed, use systemctl command; otherwise, use the service/chkconfig commands
if [ -f "/usr/bin/systemctl" ] ; then
  service_util="/usr/bin/systemctl"
else
  service_util="/sbin/service"
  chkconfig_util="/sbin/chkconfig"
fi

# If disable is not specified in arg1, set variables to enable services.
# Otherwise, variables are to be set to disable services.
if [ "$service_state" != 'disable' ] ; then
  service_state="enable"
  service_operation="start"
  chkconfig_state="on"
else
  service_state="disable"
  service_operation="stop"
  chkconfig_state="off"
fi

# If chkconfig_util is not empty, use chkconfig/service commands.
if ! [ "x$chkconfig_util" = x ] ; then
  $service_util $service $service_operation
  $chkconfig_util --level 0123456 $service $chkconfig_state
else
  $service_util $service_operation $service
  $service_util $service_state $service
fi

# Test if local variable xinetd is empty using non-bashism.
# If empty, then xinetd is not being used.
if ! [ "x$xinetd" = x ] ; then
  grep -qi disable /etc/xinetd.d/$xinetd && \

  if ! [ "$service_operation" != 'disable' ] ; then
    /usr/bin/sed -i "s/disable.*/disable         = no/gI" /etc/xinetd.d/$xinetd
  else
    /usr/bin/sed -i "s/disable.*/disable         = yes/gI" /etc/xinetd.d/$xinetd
  fi
fi

}

service_command enable pcscd.socket

# Configure the expected /etc/pam.d/system-auth{,-ac} settings directly
#
# The code below will configure system authentication in the way smart card
# logins will be enabled, but also user login(s) via other method to be allowed
#
# NOTE: It is not possible to use the 'authconfig' command to perform the
#       remediation for us, because call of 'authconfig' would discard changes
#       for other remediations (see RH BZ#1357019 for details)
#
#	Therefore we need to configure the necessary settings directly.
#

# Define system-auth config location
SYSTEM_AUTH_CONF="/etc/pam.d/system-auth"
# Define expected 'pam_env.so' row in $SYSTEM_AUTH_CONF
PAM_ENV_SO="auth.*required.*pam_env.so"

# Define 'pam_succeed_if.so' row to be appended past $PAM_ENV_SO row into $SYSTEM_AUTH_CONF
SYSTEM_AUTH_PAM_SUCCEED="\
auth        \[success=1 default=ignore\] pam_succeed_if.so service notin \
login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver quiet use_uid"
# Define 'pam_pkcs11.so' row to be appended past $SYSTEM_AUTH_PAM_SUCCEED
# row into SYSTEM_AUTH_CONF file
SYSTEM_AUTH_PAM_PKCS11="\
auth        \[success=done authinfo_unavail=ignore ignore=ignore default=die\] \
pam_pkcs11.so nodebug"

# Define smartcard-auth config location
SMARTCARD_AUTH_CONF="/etc/pam.d/smartcard-auth"
# Define 'pam_pkcs11.so' auth section to be appended past $PAM_ENV_SO into $SMARTCARD_AUTH_CONF
SMARTCARD_AUTH_SECTION="\
auth        [success=done ignore=ignore default=die] pam_pkcs11.so wait_for_card card_only"
# Define expected 'pam_permit.so' row in $SMARTCARD_AUTH_CONF
PAM_PERMIT_SO="account.*required.*pam_permit.so"
# Define 'pam_pkcs11.so' password section
SMARTCARD_PASSWORD_SECTION="\
password    required      pam_pkcs11.so"

# First Correct the SYSTEM_AUTH_CONF configuration
if ! grep -q 'pam_pkcs11.so' "$SYSTEM_AUTH_CONF"
then
	# Append (expected) pam_succeed_if.so row past the pam_env.so into SYSTEM_AUTH_CONF file
	/usr/bin/sed -i --follow-symlinks -e '/^'"$PAM_ENV_SO"'/a '"$SYSTEM_AUTH_PAM_SUCCEED" "$SYSTEM_AUTH_CONF"
	# Append (expected) pam_pkcs11.so row past the pam_succeed_if.so into SYSTEM_AUTH_CONF file
	/usr/bin/sed -i --follow-symlinks -e '/^'"$SYSTEM_AUTH_PAM_SUCCEED"'/a '"$SYSTEM_AUTH_PAM_PKCS11" "$SYSTEM_AUTH_CONF"
fi

# Then also correct the SMARTCARD_AUTH_CONF
if ! grep -q 'pam_pkcs11.so' "$SMARTCARD_AUTH_CONF"
then
	# Append (expected) SMARTCARD_AUTH_SECTION row past the pam_env.so into SMARTCARD_AUTH_CONF file
	/usr/bin/sed -i --follow-symlinks -e '/^'"$PAM_ENV_SO"'/a '"$SMARTCARD_AUTH_SECTION" "$SMARTCARD_AUTH_CONF"
	# Append (expected) SMARTCARD_PASSWORD_SECTION row past the pam_permit.so into SMARTCARD_AUTH_CONF file
	/usr/bin/sed -i --follow-symlinks -e '/^'"$PAM_PERMIT_SO"'/a '"$SMARTCARD_PASSWORD_SECTION" "$SMARTCARD_AUTH_CONF"
fi

# Perform /etc/pam_pkcs11/pam_pkcs11.conf settings below
# Define selected constants for later reuse
SP="[:space:]"
PAM_PKCS11_CONF="/etc/pam_pkcs11/pam_pkcs11.conf"

# Ensure OCSP is turned on in $PAM_PKCS11_CONF
# 1) First replace any occurrence of 'none' value of 'cert_policy' key setting with the correct configuration
/usr/bin/sed -i "s/^[$SP]*cert_policy[$SP]\+=[$SP]\+none;/\t\tcert_policy = ca, ocsp_on, signature;/g" "$PAM_PKCS11_CONF"
# 2) Then append 'ocsp_on' value setting to each 'cert_policy' key in $PAM_PKCS11_CONF configuration line,
# which does not contain it yet
/usr/bin/sed -i "/ocsp_on/! s/^[$SP]*cert_policy[$SP]\+=[$SP]\+\(.*\);/\t\tcert_policy = \1, ocsp_on;/" "$PAM_PKCS11_CONF"
sleep 2
#
#### NETWORK CONFIG AND FIREWALLS ####
#
echo "*** INSTALL LIBRESWAN PACKAGE ***"
yum -y install libreswan
sleep 2
#
echo "*** ENSURE LOG ROTATE RUNS PERIODICALLY ***"
/usr/bin/sed -i 's/weekly/daily/g' /etc/logrotate.conf
sleep 2
#
#### SYSTEM ACCOUNTING WITH AUDITD ####
#
echo "*** CONFIGURE AUDITD SPACE_LEFT ACTION ON LOW DISK SPACE ***"
var_auditd_space_left_action="email"

grep -q ^space_left_action /etc/audit/auditd.conf && \
  /usr/bin/sed -i "s/space_left_action.*/space_left_action = $var_auditd_space_left_action/g" /etc/audit/auditd.conf
if ! [ $? -eq 0 ]; then
    echo "space_left_action = $var_auditd_space_left_action" >> /etc/audit/auditd.conf
fi
sleep 2
#
echo "*** CONFIGURE AUDITD ADMIN_SPACE_LEFT ACTION ON LOW DISK SPACE ***"
var_auditd_admin_space_left_action="single"

grep -q ^admin_space_left_action /etc/audit/auditd.conf && \
  /usr/bin/sed -i "s/admin_space_left_action.*/admin_space_left_action = $var_auditd_admin_space_left_action/g" /etc/audit/auditd.conf
if ! [ $? -eq 0 ]; then
    echo "admin_space_left_action = $var_auditd_admin_space_left_action" >> /etc/audit/auditd.conf
fi
sleep 2
#
echo "*** CONFIGURE AUDITD TO USE AUDISPD SYSLOG PLUGIN ***"
grep -q ^active /etc/audisp/plugins.d/syslog.conf && \
  /usr/bin/sed -i "s/active.*/active = yes/g" /etc/audisp/plugins.d/syslog.conf
if ! [ $? -eq 0 ]; then
    echo "active = yes" >> /etc/audisp/plugins.d/syslog.conf
fi
/usr/sbin/service auditd stop
sleep 4
/usr/sbin/service auditd start
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER TIME THROUGH ADJTIMEX ***"
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER TIME THROUGH SETTIMEOFDAY ***"
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER TIME THROUGH STIME ***"
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER TIME THROUGH CLOCK_SETTIME ***"
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(/usr/bin/getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S clock_settime -F a0=.* \(-F key=\|-k \).*"
	GROUP="clock_settime"
	FULL_RULE="-a always,exit -F arch=$ARCH -S clock_settime -F a0=0x0 -k time-change"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER THE LOCALTIME FILE ***"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
fix_audit_watch_rule "augenrules" "/etc/localtime" "wa" "audit_time_rules"
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - CHMOD ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - CHOWN ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FCHMOD ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FCHMODAT ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FCHOWN ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FCHOWNAT ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FREMOVEXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - FSETXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - LCHOWN ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - LREMOVEXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - LSETXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - REMOVEXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS DISCRETIONARY ACCESS CONTROLS - SETXATTR ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY USER/GROUP INFOR ***"
# Perform the remediation
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/group" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/group" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/passwd" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/shadow" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS NETWORK ENV ***"
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="set\(host\|domain\)name"
	FULL_RULE="-a always,exit -F arch=$ARCH -S sethostname -S setdomainname -k audit_rules_networkconfig_modification"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"
sleep 2
#
echo "*** RECORD EVENTS THAT MODIFY THE SYSTEMS MANADATORY ACCESS CONTROLS ***"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/selinux/" "wa" "MAC-policy"
fix_audit_watch_rule "augenrules" "/etc/selinux/" "wa" "MAC-policy"
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER LOGON AND LOGOUT EVENT ***"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/tallylog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/tallylog" "wa" "logins"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/faillock/" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/run/faillock/" "wa" "logins"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/lastlog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/lastlog" "wa" "logins"
sleep 2
#
echo "*** RECORD ATTEMPTS TO ALTER PROCESS AND SESSION INITIATION INFOR ***"
# Perform the remediation
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/utmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/run/utmp" "wa" "session"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/btmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/btmp" "wa" "session"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/wtmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/wtmp" "wa" "session"
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS UNAUTHORIZED ACCESS ATTTEMPTS TO FILES ***"
# Perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

	# First fix the -EACCES requirement
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(creat\|open\|truncate\)"
	FULL_RULE="-a always,exit -F arch=$ARCH -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"

	# Then fix the -EPERM requirement
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k *"
	# No need to change content of $GROUP variable - it's the same as for -EACCES case above
	FULL_RULE="-a always,exit -F arch=$ARCH -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"

done
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS INFOR ON THE USE OF PRIV COMMANDS ***"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function perform_audit_rules_privileged_commands_remediation {
#
# Load function arguments into local variables
local tool="$1"
local min_auid="$2"

# Check sanity of the input
if [ $# -ne "2" ]
then
        echo "Usage: perform_audit_rules_privileged_commands_remediation 'auditctl | augenrules' '500 | 1000'"
        echo "Aborting."
        exit 1
fi

declare -a files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then:
# * add '/etc/audit/audit.rules'to the list of files to be inspected,
# * specify '/etc/audit/audit.rules' as the output audit file, where
#   missing rules should be inserted
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("/etc/audit/audit.rules")
        output_audit_file="/etc/audit/audit.rules"
#
# If the audit tool is 'augenrules', then:
# * add '/etc/audit/rules.d/*.rules' to the list of files to be inspected
#   (split by newline),
# * specify /etc/audit/rules.d/privileged.rules' as the output file, where
#   missing rules should be inserted
elif [ "$tool" == 'augenrules' ]
then
        IFS=$'\n' files_to_inspect=($(/usr/bin/find /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -print))
        output_audit_file="/etc/audit/rules.d/privileged.rules"
fi

# Obtain the list of SUID/SGID binaries on the particular system (split by newline)
# into privileged_binaries array
IFS=$'\n' privileged_binaries=($(/usr/bin/find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null))

# Keep list of SUID/SGID binaries that have been already handled within some previous iteration
declare -a sbinaries_to_skip=()

# For each found sbinary in privileged_binaries list
for sbinary in "${privileged_binaries[@]}"
do

        # Replace possible slash '/' character in sbinary definition so we could use it in sed expressions below
        sbinary_esc=${sbinary//$'/'/$'\/'}
        # Check if this sbinary wasn't already handled in some of the previous iterations
        # Return match only if whole sbinary definition matched (not in the case just prefix matched!!!)
        if [[ $(/usr/bin/sed -ne "/${sbinary_esc}$/p" <<< ${sbinaries_to_skip[@]}) ]]
        then
                # If so, don't process it second time & go to process next sbinary
                continue
        fi

        # Reset the counter of inspected files when starting to check
        # presence of existing audit rule for new sbinary
        local count_of_inspected_files=0

        # For each audit rules file from the list of files to be inspected
        for afile in "${files_to_inspect[@]}"
        do

                # Search current audit rules file's content for match. Match criteria:
                # * existing rule is for the same SUID/SGID binary we are currently processing (but
                #   can contain multiple -F path= elements covering multiple SUID/SGID binaries)
                # * existing rule contains all arguments from expected rule form (though can contain
                #   them in arbitrary order)

                base_search=$(/usr/bin/sed -e "/-a always,exit/!d" -e "/-F path=${sbinary_esc}$/!d"   \
                                  -e "/-F path=[^[:space:]]\+/!d" -e "/-F perm=.*/!d"       \
                                  -e "/-F auid>=${min_auid}/!d" -e "/-F auid!=4294967295/!d"  \
                                  -e "/-k privileged/!d" $afile)

                # Increase the count of inspected files for this sbinary
                count_of_inspected_files=$((count_of_inspected_files + 1))

                # Define expected rule form for this binary
                expected_rule="-a always,exit -F path=${sbinary} -F perm=x -F auid>=${min_auid} -F auid!=4294967295 -k privileged"

                # Require execute access type to be set for existing audit rule
                exec_access='x'

                # Search current audit rules file's content for presence of rule pattern for this sbinary
                if [[ $base_search ]]
                then

                        # Current audit rules file already contains rule for this binary =>
                        # Store the exact form of found rule for this binary for further processing
                        concrete_rule=$base_search

                        # Select all other SUID/SGID binaries possibly also present in the found rule
                        IFS=$'\n' handled_sbinaries=($(grep -o -e "-F path=[^[:space:]]\+" <<< $concrete_rule))
                        IFS=$' ' handled_sbinaries=(${handled_sbinaries[@]//-F path=/})

                        # Merge the list of such SUID/SGID binaries found in this iteration with global list ignoring duplicates
                        sbinaries_to_skip=($(for i in "${sbinaries_to_skip[@]}" "${handled_sbinaries[@]}"; do echo $i; done | sort -du))

                        # Separate concrete_rule into three sections using hash '#'
                        # sign as a delimiter around rule's permission section borders
                        concrete_rule=$(echo $concrete_rule | /usr/bin/sed -n "s/\(.*\)\+\(-F perm=[rwax]\+\)\+/\1#\2#/p")

                        # Split concrete_rule into head, perm, and tail sections using hash '#' delimiter
                        IFS=$'#' read rule_head rule_perm rule_tail <<<  "$concrete_rule"

                        # Extract already present exact access type [r|w|x|a] from rule's permission section
                        access_type=${rule_perm//-F perm=/}

                        # Verify current permission access type(s) for rule contain 'x' (execute) permission
                        if ! grep -q "$exec_access" <<< "$access_type"
                        then

                                # If not, append the 'x' (execute) permission to the existing access type bits
                                access_type="$access_type$exec_access"
                                # Reconstruct the permissions section for the rule
                                new_rule_perm="-F perm=$access_type"
                                # Update existing rule in current audit rules file with the new permission section
                                /usr/bin/sed -i "s#${rule_head}\(.*\)${rule_tail}#${rule_head}${new_rule_perm}${rule_tail}#" $afile

                        fi

                # If the required audit rule for particular sbinary wasn't found yet, insert it under following conditions:
                #
                # * in the "auditctl" mode of operation insert particular rule each time
                #   (because in this mode there's only one file -- /etc/audit/audit.rules to be inspected for presence of this rule),
                #
                # * in the "augenrules" mode of operation insert particular rule only once and only in case we have already
                #   searched all of the files from /etc/audit/rules.d/*.rules location (since that audit rule can be defined
                #   in any of those files and if not, we want it to be inserted only once into /etc/audit/rules.d/privileged.rules file)
                #
                elif [ "$tool" == "auditctl" ] || [[ "$tool" == "augenrules" && $count_of_inspected_files -eq "${#files_to_inspect[@]}" ]]
                then

                        # Current audit rules file's content doesn't contain expected rule for this
                        # SUID/SGID binary yet => append it
                        echo $expected_rule >> $output_audit_file
                fi

        done

done

}

perform_audit_rules_privileged_commands_remediation "auditctl" "1000"
perform_audit_rules_privileged_commands_remediation "augenrules" "1000"
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS INFOR ON EXPORTING TO MEDIA ***"
# Perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="mount"
	FULL_RULE="-a always,exit -F arch=$ARCH -S mount -F auid>=1000 -F auid!=4294967295 -k export"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS FILE DELETION EVENTS BY USER ***"
# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(rmdir\|unlink\|rename\)"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS SYSTEM ADMIN ACTIONS ***"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sudoers" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers" "wa" "actions"
sleep 2
#
echo "*** ENSURE AUDITD COLLECTS INFOR ON KERNEL MODULE LOADING AND UNLOADING ***"
# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit kernel modules can't be loaded / unloaded on 64-bit kernel =>
#       it's not required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule. Therefore for
#       each system it's enought to check presence of system's native rule form.
[ $(/usr/bin/getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(init\|delete\)_module"
	FULL_RULE="-a always,exit -F arch=$ARCH -S init_module -S delete_module -k modules"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(/usr/bin/expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(/usr/bin/sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(/usr/bin/sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset $IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                /usr/bin/sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset $IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/insmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/insmod" "x" "modules"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/rmmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/rmmod" "x" "modules"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset $IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | /usr/bin/cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        /usr/bin/touch "$files_to_inspect"
                        /usr/bin/chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(/usr/bin/sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                /usr/bin/sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/modprobe" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/modprobe" "x" "modules"
sleep 2
#
echo "*** MAKE THE AUDITD CONFIG IMMUTABLE ***"
# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-e .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-e 2' rule should be placed as the last rule in the configuration
/usr/bin/find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -exec /usr/bin/sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-e 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d/immutable.rules		(for augenrules case)

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration immutable per security requirements' >> $AUDIT_FILE
	echo '# Reboot is required to change audit rules once this setting is applied' >> $AUDIT_FILE
	echo '-e 2' >> $AUDIT_FILE
done
sleep 2
#
echo "*** SECURE SSHD ***"
echo
/home/ecrosby/scripts_repo/configs/Fed_sshd_ch.sh
echo
sleep 2
#
echo "*** DONE ***"
sleep 2
