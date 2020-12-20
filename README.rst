Blocklister
===========

``Blocklister`` generates MikroTik Router OS compatible address-lists from
commonly known Internet Blocklists such as `iblocklist`_ and `DShield`_. The
lists are updated once every 2 days. ``Blocklister`` is heavily inspired by
`Joshaven Potter's blog post`_.

Currently supported lists
-------------------------

Here a list of currently supported lists. All of the original sources are linked
here.

* Ads - https://www.iblocklist.com/list?list=dgxtneitpuvgqqcpfulq
* Spyware - http://list.iblocklist.com/?list=bt_spyware
* Level1 - http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw
* Level2 - http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw
* Level3 - http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh
* Edu - http://list.iblocklist.com/?list=imlmncgrkbnacgcwfjvh
* Proxy - http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb
* Badpeers - http://list.iblocklist.com/?list=cwworuawihqvocglcoss
* Microsoft - http://list.iblocklist.com/?list=xshktygkujudfnjfioro
* Spider - http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy
* Hijacked - http://list.iblocklist.com/?list=usrcshglbiilevmyfhse
* Dshield - http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv
* Spamhausdrop - https://www.spamhaus.org/drop/drop.txt
* Spamhausedrop - https://www.spamhaus.org/drop/edrop.txt
* Blocklistde_All - http://lists.blocklist.de/lists/all.txt
* Blocklistde_Ssh - http://lists.blocklist.de/lists/ssh.txt
* Blocklistde_Mail - http://lists.blocklist.de/lists/mail.txt
* Blocklistde_Imap - http://lists.blocklist.de/lists/imap.txt
* Blocklistde_Apache - http://lists.blocklist.de/lists/apache.txt
* Blocklistde_Ftp - http://lists.blocklist.de/lists/ftp.txt
* Blocklistde_Strongips - http://lists.blocklist.de/lists/strongips.txt


Install
-------

To install ``Blocklister`` on your machine make sure you have `python 2.7`_ or
`python 3`_ with `virtualenv`_ installed. Follow
the next few steps to get the application up and running with a dedicated user
and behind an `Apache Webserver`_.


Dependencies
~~~~~~~~~~~~

The dependencies listed here are meant for `Ubuntu 14.04`_.

.. code-block:: bash

    sudo apt-get install apache2 libapache2-mod-wsgi python-virtualenv
    python-dev supervisor


Setup user
~~~~~~~~~~

In this step we are going to create an individual user for ``Blocklister`` and
also create a folders for log files and for the `wsgi` script we are going to
use later on in `apache`_.

.. code-block:: bash

    sudo useradd -c "Blocklister User" -d /var/www/blocklister -m blocklister
    sudo install -d -m 775 -o www-data -g blocklister /var/www/blocklister/logs
    sudo install -d -m 755 -o blocklister -g blocklister /var/www/blocklister/wsgi


Install application
~~~~~~~~~~~~~~~~~~~

This will get you the latest version. The package hasn't been published on
`pypi`_ yet.

.. code-block:: bash

    sudo -u blocklister -i
    virtualenv env
    ./env/bin/pip install http://www.github.com/flazzarini/archive/master.zip

Configuration
~~~~~~~~~~~~~

The configuration file can be put in one of the following places
``/etc/blocklister/blocklister.conf``, ``~/.blocklister.conf`` or
``~/blocklister.conf``. The following options are available.

================ ===========================================================
 Parameter        Description
================ ===========================================================
store             Disk location to be used for storage
update_interval   Update interval for Updater Daemon (in seconds)
refresh_list      Refresh lists after x days (in days)
deduplicate       Summarize sequential IPs into ranges
================ ===========================================================

.. code-block:: ini

    [blocklister]
    store = /tmp
    update_interval = 120
    refresh_list = 2
    deduplicate = true


Updater Daemon
~~~~~~~~~~~~~~

Next we will setup the ``Updater`` daemon. We are going to use `supervisor`_ for
this. In order to do this add the following configuration file to
``/etc/supervisor/conf.d/blocklister-updater.conf``.

.. code-block:: ini

    [program:blocklister-updater]
    command=/var/www/blocklister/env/bin/blocklister-updater
    directory=/var/www/blocklister/
    autostart=true
    user=blocklister
    stderr_logfile=/var/www/blocklister/logs/updater.log
    stderr_capture_maxbytes=2MB
    environment=HOME="/var/www/blocklister",USER="blocklister"

Next start ``supervisorctl`` and reread the configuration file and fire up
``blocklister-updater``.

.. code-block:: bash

    sudo supervisorctl
    supervisor> reread
    blocklister-updater: available
    supervisor> update
    blocklister-updater: added process group
    supervisor> status
    blocklister-updater              RUNNING    pid 9535, uptime 0:00:03


WSGI Script
~~~~~~~~~~~

Next we are going to place the wsgi script into
``/var/www/blocklister/wsgi/blocklister.wsgi``. This file will be needed in the
next step to get apache up and running.

.. code-block:: python

    activate_this = "/var/www/blocklister/env/bin/activate_this.py"
    execfile(activate_this, dict(__file__=activate_this))

    from blocklister.main import app as application


Apache Config
~~~~~~~~~~~~~

Now all that's left to do is to get apache up and running. First make sure that
you have ``mod-wsgi`` enabled.

.. code-block:: bash

    a2enmod wsgi
    service apache2 reload

Now put the following content into
``/etc/apache2/sites-available/blocklister.conf``.

.. code-block:: xml

    <VirtualHost *:80>
        ServerAdmin blocklister@yourdomain.org
        ServerName blocklister.yourdomain.org
        ServerAlias blocklister

        WSGIDaemonProcess blocklister user=blocklister group=blocklister threads=5
        WSGIScriptAlias / /var/www/blocklister/wsgi/blocklister.wsgi

        <Directory /var/www/blocklister>
            WSGIProcessGroup blocklister
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>

        # Log Files
        LogLevel warn
        CustomLog /var/www/blocklister/logs/access.log combined
        ErrorLog  /var/www/blocklister/logs/error.log
    </VirtualHost>

Next enable the site and reload `apache`_, and the site should be up and running.

.. code-block:: bash

    sudo a2ensite blocklister
    sudo service apache2 reload


Issues or Requests
------------------

For issues and requests please use the issue tracker on `github`_ or `email
me`_.


.. _iblocklist: https://www.iblocklist.com
.. _DShield: http://feeds.dshield.org/block.txt
.. _Joshaven Potter's blog post: http://joshaven.com/resources/tricks/mikrotik-automatically-updated-address-list
.. _python 2.7: http://www.python.org
.. _python 3: http://www.python.org
.. _virtualenv: https://virtualenv.pypa.io
.. _Apache Webserver: http://www.apache.org
.. _apache: http://www.apache.org
.. _Ubuntu 14.04: http://www.ubuntu.com
.. _pypi: http://www.pypi.org
.. _supervisor: http://www.supervisord.org
.. _github: http://www.github.com
.. _email me: flazzarini@gmail.com
