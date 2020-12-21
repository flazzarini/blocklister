# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|
    # Basic Box Configurations
    config.vm.box = "ubuntu/xenial32"
    config.vm.network "forwarded_port", guest: 80, host: 8080

    # Fix for ttyname failed error messages
    config.vm.provision :shell, :inline => "(grep -q 'mesg n' /root/.profile && sed -i '/mesg n/d' /root/.profile && echo 'Ignore the previous error, fixing this now...') || exit 0;"

    # Dependencies
    config.vm.provision :shell, :inline => "sudo apt-get -y install apache2 libapache2-mod-wsgi python-virtualenv python-dev python-setuptools python-pip supervisor"

    # Setup User
    config.vm.provision :shell, :inline => "sudo getent passwd blocklister >/dev/null 2>&1 || sudo useradd -c 'Blocklister User' -d /var/www/blocklister -m blocklister"

    # Setup Folders
    config.vm.provision :shell, :inline => "sudo install -d -m 775 -o www-data -g blocklister /var/www/blocklister/logs"
    config.vm.provision :shell, :inline => "sudo install -d -m 755 -o blocklister -g blocklister /var/www/blocklister/wsgi"
    config.vm.provision :shell, :inline => "sudo install -d -m 755 -o blocklister -g blocklister /var/www/blocklister/conf"
    config.vm.provision :shell, :inline => "[ -d /var/www/blocklister/env ] || sudo -u blocklister virtualenv /var/www/blocklister/env"

    # Prepare/Install python package
    config.vm.provision :shell, :inline => "cd /vagrant && python setup.py sdist"
    config.vm.provision :shell, :inline => "sudo -u blocklister -i"
    config.vm.provision :shell, :inline => "cd /vagrant && PKG_NAME=$(python setup.py --fullname) && cd /var/www/blocklister && ./env/bin/pip install /vagrant/dist/$PKG_NAME.tar.gz"
    config.vm.provision :shell, :inline => "exit"

    # Prepare Updater Deamon setup using supervisor
    config.vm.provision :shell, :inline => "sudo cp /vagrant/vagrantfiles/blocklister-updater.conf /etc/supervisor/conf.d/blocklister-updater.conf"
    config.vm.provision :shell, :inline => "sudo service supervisor restart"

    # Prepare Apache config
    config.vm.provision :shell, :inline => "sudo -u blocklister -i"
    config.vm.provision :shell, :inline => "cp /vagrant/vagrantfiles/blocklister.wsgi /var/www/blocklister/wsgi/"
    config.vm.provision :shell, :inline => "cp /vagrant/vagrantfiles/logging.ini /var/www/blocklister/"
    config.vm.provision :shell, :inline => "exit"
    config.vm.provision :shell, :inline => "sudo cp /vagrant/vagrantfiles/apache2-blocklister /etc/apache2/sites-available/blocklister.conf"
    config.vm.provision :shell, :inline => "sudo a2ensite blocklister"
    config.vm.provision :shell, :inline => "sudo a2dissite 000-default"
    config.vm.provision :shell, :inline => "sudo service apache2 reload"

    # Cleanup
    config.vm.provision :shell, :inline => "sudo apt-get clean all"
end
