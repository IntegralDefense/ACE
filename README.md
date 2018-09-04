# ACE - Analysis Correlation Engine

![Analyst using ACE](analyst_on_ace.png)

John Davison gave a talk on the development of this tool set at Bsides Cincinnati in 2015. You can see his talk below.
[![Automated Detection Strategies](http://img.youtube.com/vi/okMkF-NYCHk/0.jpg)](https://youtu.be/okMkF-NYCHk)

## Super fast How-To
1. Clean Ubuntu 18 install.
2. Create username/group ace/ace.
3. Add ace to sudo.
4. Login as user ace.
5. `sudo mkdir /opt/ace && sudo chown ace:ace /opt/ace && cd /opt/ace`
6. `git clone https://github.com/IntegralDefense/ACE.git .`
7. `./installer/source_install`
8. `source load_environment`
8. `./ace add-user username email_address`
9. Goto https://127.0.0.1:5000/ace/ or what IP address you're using.

## Documentation

View ACE's full documentaion here: [https://seanm17-ace.readthedocs.io/en/latest/](https://seanm17-ace.readthedocs.io/en/latest/)
