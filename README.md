# ACE - Analysis Correlation Engine

ACE is a detection system and automation framework. ACE’s foundation is its engine for recursive analysis and its intuitive presentation to your analysts.

Send your alerts to ACE and let ACE handle the ordinary, manual, redundant, and repetitive tasks of collecting, combining, and relating data. ACE will then contextually and intuitively present all the right data to the analyst, allowing for a quick, high confidence determination to be made.

Got some new analysis that can be automated? Awesome! Add your automation, and let ACE keep working for you.

![Analyst using ACE](docs/_static/recursive-analysis-and-contextual-presentation.png)

ACE **is NOT** a SIEM... but, it *kind of*, *sort of* can act like one, if that's your thing.

For the most part, custom hunting tools send alerts to ACE using ACE’s client library (API wrapper). ACE then gets to work by taking whatever detectable conditions it’s given and spirals out through its recursive analysis of observables, hitting as many detection points as possible across the attack surface.

ACE **is** ..

* an email scanner
* a detection tool set and platform
* an automation framework
* a recursive file scanner
* a URL crawler and cacher
* a system for automated, recursive, data analysis and correlation
* more things that could be added to this list...

ACE is the implementation of a proven detection strategy, a framework for automating analysis, a central platform to launch and manage incident response activates, an email scanner, and much more.

### Major Features

+ Email Scanning
+ Recursive File Scanning
+ URL Crawling and Content Caching
+ Intuitive Alert Presentation
+ Recursive Data Analysis & Correlation
+ Central Analyst Interface
+ Event and Incident Management
+ Intel Ingestion
+ Modular Design for extending automation

## The Super Fast, Getting Started Steps
1. Clean Ubuntu 18 install.
2. Create username/group ace/ace.
3. Add ace to sudo.
4. Login as user ace.
5. `sudo mkdir /opt/ace && sudo chown ace:ace /opt/ace && cd /opt/ace`
6. `git clone https://github.com/IntegralDefense/ACE.git .`
7. `./installer/source_install`
8. `source load_environment`
8. `./ace add-user username email_address`
9. Goto https://127.0.0.1:5000/ace/ or whatever IP address you're using.


## Built for the InfoSec Team

Regardless of skill level, ACE greatly reduces the time it takes an analyst to make a high confidence alert disposition. This reduction in time-to-disposition, coupled with the appropriate hunting and tuning mindset, means that security teams can greatly increase their attack surface coverage, all while utilizing the same amount of analyst time and practically eliminating alert fatigue. Optimization good, alert fatigue bad.

![Analyst using ACE](docs/_static/analyst_on_ace.png)

## Philosophy

For a more in-depth understanding of the philosophy behind ACE, see the talk that John Davison gave on the development of the ACE tool set at BSides Cincinnati in 2015.

[![Automated Detection Strategies](http://img.youtube.com/vi/okMkF-NYCHk/0.jpg)](https://youtu.be/okMkF-NYCHk)


## Documentation

View ACE's full documentation here: [https://seanm17-ace.readthedocs.io/en/latest/](https://seanm17-ace.readthedocs.io/en/latest/)

