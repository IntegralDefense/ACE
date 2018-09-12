# ACE - Analysis Correlation Engine

ACE **_is NOT_** a SIEM.

ACE **_is_** ..
* an email scanner
* a detection tool set
* an automation framework
* a recursive file scanner
* a URL crawler and cacher
* an automated, recursive, data analysis and correlation system
* and more..

ACE is a system for automating the ordinary, manual, redundant, and repetitive tasks of collecting, combining, and relating data, in such a way, as to present security analysts with all the right data needed to give a quick, high confidence disposition.

### Major Features

+ email scanning
+ recursive file scanning
+ URL crawling and content caching
+ intuitive presentation
+ recursive data analysis and correlation
+ modular, bolt-on design
+ Central and singular interface
+ Event management
+ Intel ingestion

## The Super Fast, Getting Started
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


## Built for the InfoSec Team

Regardless of skill level, ACE greatly reduces the time it takes an analyst to make a high confidence disposition. This reduction in time-to-disposition, coupled with the appropriate hunting and tuning mindset, means that security teams can greatly increase their attack surface coverage, all while utilizing the same amount of analyst time and practically eliminating alert fatigue.

![Analyst using ACE](docs/_static/analyst_on_ace.png)

## Philosophy

For a more in-depth understanding of the philosophy behind ACE, see the talk that John Davison gave on the development of the ACE tool set at Bsides Cincinnati in 2015.

[![Automated Detection Strategies](http://img.youtube.com/vi/okMkF-NYCHk/0.jpg)](https://youtu.be/okMkF-NYCHk)


## Documentation

View ACE's full documentaion here: [https://seanm17-ace.readthedocs.io/en/latest/](https://seanm17-ace.readthedocs.io/en/latest/)

