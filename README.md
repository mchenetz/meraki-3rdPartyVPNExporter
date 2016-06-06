# Meraki 3rd Party VPN exporter
Experimental Python library that utlizes my version of the Meraki Provision API

##Overview
This project has been created to export 3rd party VPNs from the Meraki cloud. This will automatically connect to the cloud and create the configuration for the other side. Currently Cisco ASA has been implemented. More firewalls are coming.

###Information
If you want to use this tool then you need to download my version of the provisioning API too. I fixed some issues in the original version and added some functionality.

### API
You need to contact Meraki to give you API access. Once enabled it will show you your API key under your profile page. In order to get your organization ID you need to look under MDM under IOS and you should find it.
