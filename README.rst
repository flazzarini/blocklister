Blocklister
===========

`Blocklister` generates MikroTik Router OS compatible address-lists from commonly
known Internet Blocklists such as iblocklist (https://www.iblocklist.com) and
DShield (http://feeds.dshield.org/block.txt). The lists are updated once every
3 days.

Install
-------

To install `Blocklister` on your machine follow these simple steps.

.. code-block:: bash

    mkdir /opt/blocklister && cd /opt/blocklister
    virtualenv env
    ./env/bin/pip install ... # TODO
