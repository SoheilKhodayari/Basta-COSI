# Basta-COSI: Cross-Origin State Inference Testing 
[![Build Status](https://travis-ci.org/boennemann/badges.svg?branch=master)](https://travis-ci.org/boennemann/badges) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg) [![Node](https://img.shields.io/badge/node%40latest-%3E%3D%206.0.0-brightgreen.svg)](https://img.shields.io/badge/node%40latest-%3E%3D%206.0.0-brightgreen.svg) [![Django Version](https://img.shields.io/pypi/djversions/djangorestframework.svg)](https://img.shields.io/pypi/djversions/djangorestframework.svg)

Basta-COSI is a comprehensive framework for the automated detection of [COSI](https://publications.cispa.saarland/3329/1/COSI.pdf) vulnerabilities / [XS-Leaks](https://xsleaks.com/). This repository contains the code for the [NDSS'20 paper: "Cross-Origin State Inference (COSI) Attacks: Leaking Web Site States through XS-Leaks"](https://publications.cispa.saarland/3329/1/COSI.pdf). 
Please note that in its current state, the code in this repository is a PoC and not a fully-fledged production-ready tool. However, part of the Basta-COSI is also integrated with the open-source [ElasTest Security Service (ESS)](https://github.com/elastest/elastest-security-service) platform. For more information, please see [here](https://elastest.eu/).

## Installation
To start using this tool, follow the steps below:
**Step 0: Prerequisites**— This project assumes you have `Python 2.7.5`, `pip` package manager and the [ZAP spider](https://www.zaproxy.org/) Installed.
**Step 1:  Python Dependencies**— In the root project directory, run following command to install the necessary Python dependencies.
```sh
$ pip install -r requirements.txt
```
**Step 2:  Setup Database**— This project uses the lightweight portable sqlite database. Run the following command in **both** of the `logserver` and `testserver` directories to create the Django models schema.
```sh
$ python manage.py migrate
```
**Step 3:  Selenium Webdrivers**— Please install the selenium web drivers of your current platform for Chrome, FireFox, and Edge (as well as any other browser you may want to include in your tests) following the official Selenium instructions [here](https://www.selenium.dev/documentation/en/webdriver/driver_requirements/). In all cases, you may need to change or adapt the `get_new_browser_driver`function in `automator\main.py` with the exact `path` of the browser drivers in your configuration.
For example, for MacOS, you can install the drivers with brew:
```
$ brew cask install geckodriver
$ brew cask install chromedriver
```
For Windows, you may put the driver `.exe` files in the `automator\browser_drivers` directory.

### Environment Configuration
The environement configuration variables can be modified under the directory: `automator/app-config.json`.
Note that initally, an example file with the name `app-config.example.json` exists and you need to make a copy of it with your own configuration, 
removing the **example** part from the name. 

An example configuration is as follow:

```
{
  "log-server-endpoint": "http://127.0.0.1:2345",
  "test-server-endpoint": "http://127.0.0.1:9000",
  "zap-api-key": "6g607t3sik9balv4hge6krpis7",
  "browser": "chrome",
  "platform": "win32",
  "states-script": "ScriptName"
}
```

- **log-server-endpoint** : specifies the endpoint in which the log server is running.
- **test-server-endpoint** : specifies the endpoint in which the test server is running.
- **zap-api-key** : the API key obtained from the ZAP GUI to be able to use ZAP.
- **browser**: the browser used for this test. Currently, options are `chrome`, `firefox` and `edge`. See section *Selenium Webdrivers* to add support for other browsers!
- **platform**: the current platform in use. It specifies which browser drivers to use. Options are `win32` for Windows and `macos` for MaxOs.
- **states-script**: the name of the selenium state script file to be used for the site(s) specfied in `local_settings.py`.
**NOTE:** Each state script for a site with id=**x** is located under `automator\x\Scripts\ScriptName.py`

Once you set this, an auto-generated LOCK file will be created in the main automator directory under the name `auto-generated-config.json` upon running the tool.

## Architecture and Folder Structure
The application is consisted of three main directories:
1. The automator folder containing the main driver program, controling and automating all application logic.
   - The directory for each website (named by its alexa rank)
   - The global application log and environment configuration file.
   - The publicsuffix.py and /cache folder for filtering and storing the URLs with the required FORMAT for each website.
   - The `main.py` driver program
   - The `crawler_find_urls` program for finding web site URLs.
   - the `crawler_and_avi` program for collecting the HTTP logs of identified URLs, and attack vector identification for static COSI attacks.
2. The testserver folder containing the server program rendering the respective attack pages.
3. The logserver folder containing the log server program storing the required test results.
4. The plugins folder containing:
   - The attack page generation module.
   - The `cosi-attack-finder` library (git submodule) as a knowledge base for **finding static COSI attacks**.
        - The `v2_attack_page_generator` module for generating attack pages.
        - **Note:** the `attack_vector_selection` is the algorithm used for finding the best attack vectors from a single attack vector database.
   - The `report-server` for testing the generated attack pages (possibly sending the inferred states to the report-server). Currently, the implementation of this feature is not fully integrated.

**Note:** The directory for each website contains the following folders:
1. `TestReports` folder containing the respective test results
2. `urls` folder containing tested urls for that particular website
3. `scripts` folder containing required selenium scripts. e.g., `loginNlogout.py`, `Auth.py`, etc.
4. `logs` folder (exists only if there is any relevant logs).

## Running the Tool 
In order to run and use the tool, take note of the followings:

### Tool Input
**Step 1**— Duplicate the site template folder located on `automator/site-template` and rename it to an integer id. 
**Step 2**— Add the id to the settings (`local_settings.py` under `testserver/main` directory).

### Customize What Would Run 
**which tests?**— Open the application main file located on `automator/main.py` and navigate down to the 'main' function, through which you can specify which test shall run by calling the respective test function.
**which sites?**— Rename the `local_settings.example.py` file under the `testserver/main` directory to `local_settings.py`, and add site entries to the `site_dict` dictionary. For example, for testing 'https://www.google.com', following is an example entry:
```
site_dict = {
        '1': ('https://www.google.com', 'google'),
}
```
Having this example config, test results would be stored under `automator\1` where `1` is the id of the site in the given dictionary.

### Run
**Step 0**— Run the ZAP tool, if it is not already running.

**Step 1**— Run the test server with the command `python manage.py runserver 9000` executed in the root of the 'testserver' directory. 
If executed successfully, the test server is accessible on "http://127.0.0.1:9000". You may pass anoher port number depending on your *app environment configuration*.

**Step 2**—  Run the log server with the command `python manage.py runserver 1234` executed in the root of the 'logserver' directory. 
The number 1234 is currently the default application port number for the log server. If executed successfully, the log server is accessible on "http://127.0.0.1:1234". You may pass anoher port number depending on your *app environment configuration*.

**Step 3**— Navigate to the root of the `automator` directory:
**3.1. URL Crawling:** (If needed) Crawl the urls for a given website by running `python crawler_find_urls.py <site-id>` where `<site-id>` is an integer representing the site identifier in the settings.

**3.2. Collect HTTP Responses:** (If needed) Run the function `main_crawl_url_response_headers(siteId)` in `automator\crawler_and_avi.py`. Specify the correct siteId and browsers. This will open up a browser, do sample inclusions (generate candidate pages by test server), and collect the HTTP traffic.

**3.3. Run Static Attacks:** Run the function `get_cosi_attacks(siteId, browser, browser_version)` in `automator\crawler_and_avi.py`. Specify the correct siteId and browsers. The results will be stored both in a global attack vector database (by SQLAlchemy) and a `.out` file stored in `automator\siteId\TestReports\Crawler`.

**3.4. Run Dynamic Attacks:** Run the main automating program for dynamic attacks with the command `python main.py` executed in the root of the 'automator' directory. Please make sure to set which tests shall run in the `main()` function at the end of this file. The results will be stored both in a global attack vector database (by SQLAlchemy) and a `.out` files stored in `automator\siteId\TestReports\<Attack-Type>`.

## Test Results

All test results will be stored in a single attack vector databse in `automator\siteId`. Test results are also available as `.out` files. 
Such test reports are available for each website under the main automater directory "{website-rank}/TestReports/{test-type}/{browser}" after running the corresponding tests, where:

1. {website-rank} is the alexa rank for the website.
2. {test-type} is the type of test e.g. "PostMessage", "ScriptInclusion", "ContentWindow", etc

For instance, the PostMessage test reports for the website "https://www.google.com" with alexa rank 1 using Chrome as browser are available under the "automator/1/TestReports/PostMessage/Chrome" directory! 

### Utility Scripts: Analyzing Test Results
Utility scripts provide various functionality for the generated test results. This includes the analysis or **comparison** of the collected data across different user states, data transformation and summarizing multiple csv files into a single test report. 
- The general command to run such scripts is `python <script-name.py> <site-id>`. 
- New script commands should be added to the `runme.py` script list.

To run all the scripts subsequently for a given site, run:
```sh
$ cd automator/utility-scripts
$ python runme.py <siteId>
```
where `<siteId>` is the identifier of the site to be tested specified on `local_settings`.


## Cite this work
If you use Basta-COSI for academic research, you are highly encouraged to cite the following [paper](https://publications.cispa.saarland/3329/1/COSI.pdf):
```
@inproceedings {ASudhodanan2020BastaCOSI,
  author = {Avinash Sudhodanan and Soheil Khodayari and Juan Caballero},
  title = {Cross-Origin State Inference (COSI) Attacks: Leaking Web Site States through XS-Leaks},
  booktitle = {Proceedings of the Network and Distributed Systems Security Symposium},
  year = {2020},
}
```
**Abstract** —In a Cross-Origin State Inference (COSI) attack, an attacker convinces a victim into visiting an attack web page, which leverages the cross-origin interaction features of the victim’s web browser to infer the victim’s state at a target web site. Multiple instances of COSI attacks have been found in the past under different names such as login detection or access detection attacks. But, those attacks only consider two states (e.g., logged in or not) and focus on a specific browser leak method (or XS-Leak). 
This work shows that mounting more complex COSI attacks such as deanonymizing the owner of an account, determining if the victim owns sensitive content, and determining the victim’s account type often requires considering more than two states.  Furthermore, robust attacks require supporting a variety of browsers since the victim’s browser cannot be predicted apriori. To address these issues, we present a novel approach to identify and build complex COSI attacks that differentiate more than two states and support multiple browsers by combining multiple attack vectors, possibly using different XS-Leaks. To enable our approach, we introduce the concept of a COSI attack class. We propose two novel techniques to generalize existing COSI attack instances into COSI attack classes and to discover new COSI attack classes. We systematically apply our techniques to existing attacks, identifying 40 COSI attack classes. As part of this process, we discover a novel XS-Leak based on window.postMessage. We implement our approach into Basta-COSI, a tool to find COSI attacks in a target web site. We apply Basta-COSI to test four stand-alone web applications and 58 popular web sites, finding COSI attacks against each of them.

## License
This project is licensed under `GNU AFFERO GENERAL PUBLIC LICENSE V3.0`. You may not use this file except in compliance with the license. You may obtain a copy of the license [here](LICENSE). 
This program is distributed on an "AS IS" BASIS in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [license](LICENSE) for more information.




