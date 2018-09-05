# ACE - Analysis Correlation Engine

ACE automates data correlation and analysis for an intuitive presentation to security analysts so a quick, high confidence disposition can be made. ACE does not automate the analyst away, instead, ACE makes the analyst's job easier by automating as much as possible for the analyst. This way, the analyst can quickly and accurately disposition alerts. The analyst's reduction in time-to-disposition means that a much larger number of alerts can be work in a day, and when combined with hunting and tuning a very broad detection net can be cast.

ACE ..
+ is an automated, recursive analysis and correlation system
+ is an email scanner
+ presents data intuitively
+ greatly reduces time-to-disposition
+ prevents alert fatigue

ACE is NOT ..
+ a SIEM!

ACE is a system for automating the orginary, manual, repeative, and redundant security analyst tasks, in such a way, as to present the security analyst all of the right data needed to give a quick, high considence disposition.



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
