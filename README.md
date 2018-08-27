# ACE

Analysis Correlation Engine

<img src="https://github.com/unixfreak0037/ACE/raw/master/analyst_on_ace.png" width="480">

John Davison gave a talk on this tool set at Bsides Cincinnati in 2015. You can see his talk below.

<a href="https://youtu.be/okMkF-NYCHk" target="_blank"><img src="http://img.youtube.com/vi/okMkF-NYCHk/0.jpg" 
alt="BSides Cinci 2015 Automated Detection Strategies" width="240" height="180" border="10" /></a>

Super fast How-To
1) Clean Ubuntu 18 install.
2) Create username/group ace/ace.
3) Add ace to sudo.
4) Login as user ace.
5) `sudo mkdir /opt/ace && sudo chown ace:ace /opt/ace && cd /opt/ace`
6) `git clone https://github.com/IntegralDefense/ACE.git .`
7) `./installer/source_install`
8) `source load_environment`
8) `./ace add-user username email_address`
9) Goto https://127.0.0.1:5000/ace/ or what IP address you're using.
