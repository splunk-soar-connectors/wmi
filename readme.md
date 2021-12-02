[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Windows Management Instrumentation (WMI) ports need to be opened up on the endpoint for the app to
run WMI commands remotely. Depending upon your setup, this configuration can be part of a Group
Policy Object (GPO) or carried out individually on the endpoint.

This app does not support proxies, and it will ignore any proxy settings.

## wmi-client-wrapper

This app makes use of the Python wmi-client-wrapper module, which is licensed under the BSD License,
Copyright (c) 2013

## wmi-client-wrapper-py3

This app makes use of the Python wmi-client-wrapper-py3 module, which is licensed under the BSD
License, Copyright (c) 2018
