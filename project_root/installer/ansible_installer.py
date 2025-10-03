#!/usr/bin/env python3
"""
Ansible Playbook for Enterprise Reporting System
Note: This is a simplified example. In a real scenario, you'd use actual Ansible YAML files.
"""

import os
import sys
from pathlib import Path

def generate_ansible_playbook():
    """Generate Ansible playbook content"""
    playbook_content = '''
---
- name: Deploy Enterprise Reporting System
  hosts: reports_servers
  become: yes
  vars:
    reports_user: "reports"
    reports_group: "reports"
    reports_home: "/opt/reports"
    reports_version: "1.0.0"
    reports_api_port: 8080
    reports_web_port: 8081

  tasks:
    - name: Create reports user
      user:
        name: "{{ reports_user }}"
        group: "{{ reports_group }}"
        home: "{{ reports_home }}"
        shell: /bin/bash
        system: yes
        state: present

    - name: Install system dependencies
      apt:
        name:
          - python3
          - python3-pip
          - python3-venv
          - git
          - curl
          - openssh-server
          - jq
        state: present
      when: ansible_os_family == "Debian"

    - name: Install system dependencies (RHEL/CentOS)
      yum:
        name:
          - python3
          - python3-pip
          - git
          - curl
          - openssh-server
          - jq
        state: present
      when: ansible_os_family == "RedHat"

    - name: Create reports directory
      file:
        path: "{{ reports_home }}"
        owner: "{{ reports_user }}"
        group: "{{ reports_group }}"
        mode: '0755'
        state: directory

    - name: Install Enterprise Reporting System
      pip:
        name: "enterprise-reporting-system=={{ reports_version }}"
        virtualenv: "{{ reports_home }}/venv"
        virtualenv_python: python3
      become_user: "{{ reports_user }}"

    - name: Initialize reports system
      command: "{{ reports_home }}/venv/bin/reports-init"
      become_user: "{{ reports_user }}"
      args:
        chdir: "{{ reports_home }}"

    - name: Create systemd service files
      template:
        src: "reports-api.service.j2"
        dest: "/etc/systemd/system/reports-api.service"
        mode: '0644'
        owner: root
        group: root

    - name: Create systemd web service file
      template:
        src: "reports-web.service.j2"
        dest: "/etc/systemd/system/reports-web.service"
        mode: '0644'
        owner: root
        group: root

    - name: Configure firewall for API
      ufw:
        rule: allow
        port: "{{ reports_api_port }}"
        proto: tcp
      when: ansible_distribution == "Ubuntu"

    - name: Configure firewall for Web Interface
      ufw:
        rule: allow
        port: "{{ reports_web_port }}"
        proto: tcp
      when: ansible_distribution == "Ubuntu"

    - name: Configure firewall for API (firewalld)
      firewalld:
        port: "{{ reports_api_port }}/tcp"
        permanent: yes
        state: enabled
        immediate: yes
      when: ansible_os_family == "RedHat"

    - name: Configure firewall for Web Interface (firewalld)
      firewalld:
        port: "{{ reports_web_port }}/tcp"
        permanent: yes
        state: enabled
        immediate: yes
      when: ansible_os_family == "RedHat"

    - name: Start and enable reports services
      systemd:
        name: "{{ item }}"
        state: started
        enabled: yes
        daemon_reload: yes
      loop:
        - reports-api
        - reports-web

    - name: Verify services are running
      systemd:
        name: "{{ item }}"
        state: started
      check_mode: yes
      loop:
        - reports-api
        - reports-web
'''
    
    # Create Ansible directory structure
    ansible_dir = Path("ansible")
    ansible_dir.mkdir(exist_ok=True)
    
    # Write the playbook
    with open(ansible_dir / "deploy-reports.yml", "w") as f:
        f.write(playbook_content)
    
    # Create inventory example
    inventory_content = '''
[reports_servers]
reports-server-01 ansible_host=192.168.1.100
reports-server-02 ansible_host=192.168.1.101

[reports_servers:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
'''
    
    with open(ansible_dir / "inventory.yml", "w") as f:
        f.write(inventory_content)
    
    # Create requirements file for Ansible roles
    requirements_content = '''
---
collections:
  - name: ansible.posix
    version: ">=1.0.0"
  - name: ansible.utils
    version: ">=2.0.0"
'''
    
    with open(ansible_dir / "requirements.yml", "w") as f:
        f.write(requirements_content)
    
    print("Ansible playbook and configuration files created in 'ansible' directory")
    print("To use:")
    print("  1. Install Ansible: pip install ansible")
    print("  2. Run: ansible-galaxy install -r ansible/requirements.yml")
    print("  3. Run: ansible-playbook -i ansible/inventory.yml ansible/deploy-reports.yml")

if __name__ == "__main__":
    generate_ansible_playbook()