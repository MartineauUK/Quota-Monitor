# Quota-Monitor
ASUS Router Monitor device throughput in real-time via the commandline, without using the TrendMicro utilities

###NOTE: _May not be compatible with HND-routers since Hardware Acceleration should be disabled_ ###

## Installation ##

###NOTE: Entware is assumed to be installed###

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:
	
	curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/Quota-Monitor/master/QuotaMonitor.sh" -o "/jffs/scripts/QuotaMonitor.sh" && chmod 755 "/jffs/scripts/QuotaMonitor.sh"
