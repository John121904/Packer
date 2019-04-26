# Packer Builds

# VMware Builds

#packer run for vmware (run.sh)
PACKER_LOG=1 packer build -var-file=./secrets.yml -var 'vcenter_username=admin_account' -var
'deploy_vsphere_user=admin_password' -var 'vcenter_password=password' -var 'elevated_password=win_passwd' -var 'winrm_password=winrm_password' win2016.json
