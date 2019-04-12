PACKER_LOG=1 packer build -var-file=./secrets.yml -var 'vcenter_password=Tester21' -var 'elevated_password=(h@ng3,M3!' -var 'winrm_password=(h@ng3,M3!' win2016.json

