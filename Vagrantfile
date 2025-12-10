BOX_IMAGE = "ubuntu/focal64"

Vagrant.configure("2") do |config|

  config.vm.boot_timeout = 600
# VM L4S Client
  config.vm.define "clientp4" do |client|
    client.vm.box = BOX_IMAGE 
    client.vm.hostname = "clientl4s-p4"
    client.vm.network "private_network", ip: "192.168.56.10", mac: "080027AAAAAA",
      virtualbox__intnet: "l4s_client-s1"
#    client.ssh.insert_key = false
#    client.ssh.private_key_path = "vagrant_key"

    client.vm.provider "virtualbox" do |vb|
      vb.name = "clientp4"
    end

    client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_l4s.yml"
    end
  end

  # VM Classic Client (Subnet 192.168.57.0/24)
  config.vm.define "classic-clientp4" do |classic_client|
    classic_client.vm.box = BOX_IMAGE 
    classic_client.vm.hostname = "classic-client"
    classic_client.vm.network "private_network", ip: "192.168.57.10", mac:"080027BBBBBB",
      virtualbox__intnet: "classic_clients-s1"
    classic_client.vm.provider "virtualbox" do |vb|
      vb.name = "classic-client-p4" 
    end
    classic_client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_classic.yml"
    end
  end

  # VM Malicious Client (Nova subnet 192.168.57.0/24)
  config.vm.define "malicious-clientp4" do |malicious_client|
    malicious_client.vm.box = BOX_IMAGE
    malicious_client.vm.hostname = "malicious-client"
    malicious_client.vm.network "private_network", ip: "192.168.57.20", mac: "080027CCCCCC",
      virtualbox__intnet: "classic_clients-s1"
    malicious_client.vm.provider "virtualbox" do |vb|
      vb.name = "malicious-client-p4" 
    end

    malicious_client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_malicious.yml"
    end
  end

  # VM switch
  config.vm.define "router_bmv2"do |switch|
    switch.vm.box = "viniciussimao/bmv2-p4"
    switch.vm.box_version = "01"
    switch.vm.hostname = "switch-bmv2"
    # --- Configurações de Hardware ---
    switch.vm.provider "virtualbox" do |vb|
      vb.memory = 4096   
      vb.cpus = 4 
      vb.name = "router_bmv2-p4"
      vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"] 
      vb.customize ["modifyvm", :id, "--nicpromisc5", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc6", "allow-all"]
    end
    # Interface enp0s8 (Interface de Gerenciamento)
    switch.vm.network "private_network", ip: "192.168.63.2", netmask: "255.255.255.252", name: "vboxnet0"

    # Interface enp0s9 (l4s_client - bmv2)
    switch.vm.network "private_network", auto_config: false, mac: "080027AAAABA",
      virtualbox__intnet: "l4s_client-s1"

    # Interface enp0s10 (Classic_Clients - bmv2)
    switch.vm.network "private_network", auto_config: false, mac: "080027AAAABB",
      virtualbox__intnet: "classic_clients-s1"

    # Interface enp0s16 (L4S servers - bmv2)
    switch.vm.network "private_network", auto_config: false, mac: "080027AAAABC",
      virtualbox__intnet: "l4s_server-s1"
    
    # Interface enp0s17(Classic Server - bmv2)
    switch.vm.network "private_network", auto_config:  false, mac: "080027AAAABD",
      virtualbox__intnet: "classic_server-s1"
    
    switch.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/router.yml"
    end
  end

  # VM Servidor (L4S)
  config.vm.define "serverp4" do |server|
    server.vm.box = BOX_IMAGE
    server.vm.hostname = "server-l4s-p4"
    server.vm.network "private_network",ip: "192.168.56.50", mac: "080027DDDDDD",
      virtualbox__intnet: "l4s_server-s1"
    server.vm.provider "virtualbox" do |vb|
      vb.name = "servidor-l4s-p4" 
    end

    server.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/server_l4s.yml"
    end
  end

  # VM Classic Server
  config.vm.define "classic-serverp4" do |classic_server|
    classic_server.vm.box = BOX_IMAGE
    classic_server.vm.hostname = "classic-server"
    classic_server.vm.network "private_network", ip: "192.168.57.50", mac: "080027EEEEEE",
      virtualbox__intnet: "classic_server-s1"
    classic_server.vm.provider "virtualbox" do |vb|
      vb.name = "peer_classic"
    end 

    classic_server.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/server_classic.yml"
    end
  end
end
