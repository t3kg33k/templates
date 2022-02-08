#/bin/bash

# Prerequisites
# The system time between the Domain Controller and RHEL server must be synchronized.
# /etc/resolv.conf is set to a DNS server that can resolve your Active Directory DNS zones
# The search domain is set to the Active Directory DNS domain

# This template assumes the Domain is test.local and the Domain Controller is DC1

yum install -y samba-client  samba-winbind samba-winbind-clients

currentTimestamp=`date +%y-%m-%d-%H:%M:%S`
prefix='/etc'

echo "Configure krb5"
krbConfFile="$prefix/krb5.conf"
krbConfFileBackup=$krbConfFile.$currentTimestamp.bak
if [ -f "$krbConfFile" ]; then
    echo backup $krbConfFile to $krbConfFileBackup
    cp $krbConfFile $krbConfFileBackup
fi
cat > "$krbConfFile" << EOF
[logging]
default = FILE:/var/log/krb5libs.log
kdc = FILE:/var/log/krb5kdc.log
admin_server = FILE:/var/log/kadmind.log

[libdefaults]
ticket_lifetime = 24000
default_realm = test.local
dns_lookup_realm = false
dns_lookup_kdc = false

[realms]
test.local = {
kdc = dc1.test.local
default_domain = test.local
}

[domain_realm]
.test.local = test.local
test.local = test.local

[appdefaults]
pam = {
     debug = false
     ticket_lifetime = 36000
     renew_lifetime = 36000
     forwardable = true
     krb4_convert = false
}
EOF

echo "Configure smb"
smbConfFile="$prefix/samba/smb.conf"
smbConfFileBackup=$smbConfFile.$currentTimestamp.bak
if [ -f "$smbConfFile" ]; then
    echo backup $smbConfFile to $smbConfFileBackup
    cp $smbConfFile $smbConfFileBackup
fi
cat > "$smbConfFile" << EOF
[global]
    security = ADS
    workgroup = test
    realm = test.local
    password server = dc1.test.local
    client use spnego = yes
    server signing = auto
    server string = Samba Server
    winbind enum users = yes
    winbind enum groups = yes
    winbind use default domain = yes
    winbind separator = +
    idmap uid = 10000-20000
    idmap gid = 10000-20000
    template shell = /bin/bash
EOF

echo "Join the domain."
service winbind stop > null 
net ads join -U administrator

if [ $? -eq 0 ]; then
    echo "Start winbind and enable it on boot."
    service winbind start
    chkconfig winbind on
    
    echo "Configure the NSS and PAM stack."
    nsswitchConfFile="$prefix/nsswitch.conf"
    nsswitchConfFileBackup=$nsswitchConfFile.$currentTimestamp.bak
    if [ -f "$nsswitchConfFile" ]; then
        cp $nsswitchConfFile $nsswitchConfFileBackup
    fi

    pamConfFile="$prefix/pam.d/system-auth"
    pamConfFileBackup=$pamConfFile.$currentTimestamp.bak
    if [ -f "$pamConfFile" ]; then
        cp $pamConfFile $pamConfFileBackup
    fi

    authConfFile="$prefix/sysconfig/authconfig"
    authConfFileBackup=$authConfFile.$currentTimestamp.bak
    if [ -f "$authConfFile" ]; then
        cp $authConfFile $authConfFileBackup
    fi

    sed -i 's/FORCELEGACY=no/FORCELEGACY=yes/' /etc/sysconfig/authconfig
    authconfig --enablewinbind --enablekrb5  --enablemkhomedir --enableforcelegacy --update  > null 
    
    echo "Verify the the system can talk to Active Directory."
    wbinfo -t
else
    echo "---------------------------------------------------"
    echo "Failed to join domain. Before running the script,"
    echo "- Ensure that the system time between the Domain Controller and RHEL server are synchronized."
    echo "- Ensure that /etc/resolv.conf is set to a DNS server that can resolve your AD DNS zones, and that the search domain is set to the AD DNS domain."
fi
