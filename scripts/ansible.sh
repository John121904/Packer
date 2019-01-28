#!/bin/bash -eux

# Configure repos
#subscription-manager register --username=${RHSM_USERNAME} --password=${RHSM_PASSWORD} --name=packer-rhel7-$(date +%Y%m%d)-${RANDOM}
subscription-manager register --org="CWT" --activationkey=${RH_ACT_KEY}
subscription-manager attach --auto
#subscription-manager attach --pool=${RHSM_POOL}
subscription-manager repos --disable=*
subscription-manager repos --enable=${ANSIBLE_REPOS} --enable=rhel-7-server-rpms
#subscription-manager repos --enable=rhel-7-server-ansible-2.7-rpms --enable=rhel-7-server-rpms

# Update to last patches
yum -y update --setopt tsflags=nodocs

# Install Ansible.
yum -y install --setopt tsflags=nodocs ansible
yum history package ansible|awk '/Install/ {print $1}' > /tmp/YUM_ID

# Configure /tmp on tmpfs
systemctl enable tmp.mount
