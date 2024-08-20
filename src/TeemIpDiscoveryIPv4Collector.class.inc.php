<?php
/*
 * @copyright   Copyright (C) 2023 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPv4Collector extends Collector
{
	protected int $iIndex;
    protected string $bSetStatusOnRegisteredIPs;
	protected string $sIPDefaultStatus;
	protected string $sIPDefaultView;
	protected string $sPingPath;
	protected string $sFpingPath;
	protected string $bFpingEnable;
	protected string $sDigPath;
	protected array $aIPv4;
	protected CollectionPlan $oCollectionPlan;
	protected array $aIPDiscoveryAttributes;
	protected array $aIPv4SubnetsList;
    protected LookupTable $oIPv4AddressIPConfigMapping;

	/**
	 * @inheritdoc
	 */
	public function Init(): void
	{
		parent::Init();

		$this->iIndex = 0;
        $this->bSetStatusOnRegisteredIPs = Utils::GetConfigurationValue('set_status_on_already_registered_ips', 'no');
		$this->sIPDefaultStatus = Utils::GetConfigurationValue('ip_default_status', 'unassigned');
		$this->sIPDefaultView = Utils::GetConfigurationValue('ip_default_view', '');
		$this->sPingPath = Utils::GetConfigurationValue('ping_absolute_path', '');
		$this->sFpingPath = Utils::GetConfigurationValue('fping_absolute_path', '');
		$this->bFpingEnable = Utils::GetConfigurationValue('fping_enable', 'yes');
		$this->sDigPath = Utils::GetConfigurationValue('dig_absolute_path', '');
		$this->aIPv4 = [];

		// Get info from the collection plan
		$this->oCollectionPlan = TeemIpDiscoveryCollectionPlan::GetPlan();
		$this->aIPDiscoveryAttributes = $this->oCollectionPlan->GetApplicationParam('params');
		$this->aIPv4SubnetsList = $this->oCollectionPlan->GetSubnetsList('ipv4');
	}

	/**
	 * @inheritdoc
	 */
	public function CheckToLaunch($aOrchestratedCollectors): bool
	{
		if (!parent::CheckToLaunch($aOrchestratedCollectors)) {
			return false;
		}

		// Make sure that TeemIp is installed
		if (!$this->oCollectionPlan->IsTeemIpInstalled()) {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4Collector will not be launched as TeemIp is not installed');
			return false;
		}
		// Make sure that a Discovery Application has been identified
		if ($this->oCollectionPlan->GetApplicationParam('uuid') == '') {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4Collector will not be launched as no IP Discovery Application has been found');
			return false;
		}
		// Make sure IPv4 discovery is orchestrated first
		if (!empty($aOrchestratedCollectors)) {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4Collector will not be launched as it doesn\'t appear to be the first one to run. Please check launch sequence!');
			return false;
		}

		return true;
	}

	/**
	 * Transform a delay into a string
	 *
	 * @param $iStart
	 * @param $iStop
	 *
	 * @return string
	 */
	protected function GetDelayAsString($iStart, $iStop)
	{
		$iDelay = $iStop - $iStart;
		$iHours = intval($iDelay / 3600);
		$iMinutes = intval(($iDelay - ($iHours * 3600)) / 60);
		$iSeconds = $iDelay - ($iHours * 3600) - ($iMinutes * 60);
		if ($iSeconds < 1) {
			$iSeconds = 1;
		}

		$sDelay = $iHours." hours, ".$iMinutes." minutes, ".$iSeconds." seconds";

		return $sDelay;
	}

	/**
	 * @inheritdoc
	 */
	public function AttributeIsOptional($sAttCode)
	{
		if ($sAttCode == 'view_id') return !$this->oCollectionPlan->IsTeemIpZoneMgmtInstalled();

		return parent::AttributeIsOptional($sAttCode);
	}

	/**
	 * Retrieve the list of all IPs already registered
	 *
	 * @return bool
	 * @throws \Exception
	 */
	protected function GetRegisteredIps()
	{
		// Build OQL to retrieve IPs
		$aSubnetsToDiscover = [];
		$sOQL = 'SELECT IPv4Address WHERE subnet_ip IN (%s)';
		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
				$aSubnetsToDiscover[] = sprintf("'%s'", $sSubnetIp);
			}
		}
		$sOQL = sprintf($sOQL, implode(',', $aSubnetsToDiscover));

		// Get IPs
		$bResult = true;
		try {
			$oRestClient = new RestClient();
			if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
				$aResult = $oRestClient->Get('IPv4Address', $sOQL, 'ip, org_id, ipconfig_id, status, view_name, responds_to_ping, responds_to_iplookup, fqdn_from_iplookup, responds_to_scan');
			} else {
				$aResult = $oRestClient->Get('IPv4Address', $sOQL, 'ip, org_id, ipconfig_id, status, responds_to_ping, responds_to_iplookup, fqdn_from_iplookup, responds_to_scan');
			}
			if ($aResult['code'] != 0) {
				Utils::Log(LOG_ERR, "{$aResult['message']} ({$aResult['code']})");
				$bResult = false;
			} else {
				if (!empty($aResult['objects'])) {
					Utils::Log(LOG_DEBUG, "---------- List of IPs already registered ----------");
					Utils::Log(LOG_DEBUG, "OQL: ".$sOQL);
					foreach ($aResult['objects'] as $sKey => $aData) {
						$aIPAttributes = $aData['fields'];
						$sIp = $aIPAttributes['ip'];
						$this->aIPv4[$sIp]['synchro_data']['primary_key'] = $sIp;
						$this->aIPv4[$sIp]['synchro_data']['ip'] = $sIp;
						$this->aIPv4[$sIp]['synchro_data']['org_id'] = $aIPAttributes['org_id'];
						$this->aIPv4[$sIp]['synchro_data']['ipconfig_id'] = $aIPAttributes['ipconfig_id'];
						$this->aIPv4[$sIp]['synchro_data']['status'] = $aIPAttributes['status'];
						if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
							$this->aIPv4[$sIp]['synchro_data']['view_id'] = $aIPAttributes['view_name'];
						}
						$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = $aIPAttributes['responds_to_ping'];
						$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = $aIPAttributes['responds_to_iplookup'];
						$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = $aIPAttributes['fqdn_from_iplookup'];
						$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] = $aIPAttributes['responds_to_scan'];
						$this->aIPv4[$sIp]['has_changed'] = 'no';

						Utils::Log(LOG_DEBUG, "IP: ".$sIp);
					}
				}
				Utils::Log(LOG_DEBUG, "---------------------------------------------");
			}
		} catch (Exception $e) {
			Utils::Log(LOG_ERR, $e->getMessage());
			$bResult = false;
		}

		return $bResult;
	}

	/**
	 * Check if an IP is in an IP range
	 *
	 * @param $iIp
	 * @param $aDHCPRanges
	 *
	 * @return bool
	 */
	protected function IsIPInDHCPRange($iIp, $aDHCPRanges)
	{
		if (!empty($aDHCPRanges)) {
			foreach ($aDHCPRanges as $sRangeName => $aIPs) {
				if ((ip2long($aIPs['firstip']) <= $iIp) && ($iIp <= ip2long($aIPs['lastip']))) {
					{
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Ping all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 *
	 * @param $sTimeStamp
	 *
	 * @return void
	 * @throws \Exception
	 */
	protected function PingIpv4Ips($sTimeStamp)
	{
		// Check if fping or ping command are available
		exec($this->sFpingPath.'fping -v', $aOutput, $iStatus);
		if (($this->bFpingEnable != 'yes') || ($iStatus == 127)) {
			exec($this->sPingPath.'ping -V', $aOutput, $iStatus);
			if ($iStatus == 127) {
				Utils::Log(LOG_ERR, "Ping command or fping command not found");
					return;
			} else $sPingCmd = $this->sPingPath.'ping';
		} else $sFpingCmd = $this->sFpingPath.'fping';

		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] != 'yes') {
				continue;
			}
			if ($aIPv4Subnet['ping_enabled'] == 'yes') {
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);

				$iIp = $iSubnetIp + 1;
				if (($this->aIPDiscoveryAttributes['ping_timeout'] == 0) || ($this->aIPDiscoveryAttributes['ping_timeout'] == '')) {
					$iTimeOut = 1;
				} else {
					$iTimeOut = $this->aIPDiscoveryAttributes['ping_timeout'];
				}
				$iNbIPsThatPing = 0;
				$iStartTime = time();
				$iStatus = -1;
				$aFPingResults = [];
				Utils::Log(LOG_INFO, "Start to ping subnet: ".$sSubnetIp);

				// fping if available
				if (isset($sFpingCmd)) exec(sprintf('%s -r1 -t%d -ga %s %s 2>&1', $sFpingCmd, $iTimeOut*1000, long2ip($iIp), long2ip($iBroadcastIp-1)), $aFPingResults);

				while ($iIp < $iBroadcastIp) {
					$sIp = long2ip($iIp);
					// Skip DHCP IP if required
					if (($aIPv4Subnet['dhcp_range_discovery_enabled'] != 'yes') && $this->IsIPInDHCPRange($iIp, $aIPv4Subnet['dhcp_ranges'])) {
						// Reset ping attribute anyway if IP is already registered
						if (array_key_exists($sIp, $this->aIPv4)) {
							if (($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'yes') ||
								($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'no')) {
								$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = 'na';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						}
						Utils::Log(LOG_DEBUG, "DHCP ".$sIp." has not been pinged");
					} else {
						if (isset($sPingCmd)) exec($sPingCmd.' -c 1 -W '.$iTimeOut.' '.$sIp, $aOutput, $iStatus);
						if ($iStatus == 0 or in_array($sIp, $aFPingResults)) {
							// IP is alive
							if (array_key_exists($sIp, $this->aIPv4)) {
								// Change data anyway as time stamp changes
								$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = 'yes';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
                                if ($this->bSetStatusOnRegisteredIPs == 'yes') {
                                    $this->aIPv4[$sIp]['synchro_data']['status'] = $this->sIPDefaultStatus;
                                }
                                $this->aIPv4[$sIp]['has_changed'] = 'yes';
							} else {
								$aValues = array(
									'primary_key' => $sIp,
									'ip' => $sIp,
									'org_id' => $aIPv4Subnet['org_id'],
									'ipconfig_id' => $aIPv4Subnet['ipconfig_id'],
									'status' => $this->sIPDefaultStatus,
									'last_discovery_date' => $sTimeStamp,
									'responds_to_ping' => 'yes',
									'responds_to_iplookup' => 'na',
									'fqdn_from_iplookup' => '',
									'responds_to_scan' => 'na',
								);
								if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
									$aValues['view_id'] = $this->sIPDefaultView;
								}
								$this->aIPv4[$sIp]['synchro_data'] = $aValues;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
							$iNbIPsThatPing += 1;
							Utils::Log(LOG_DEBUG, "Ping ".$sIp." -> OK");
						} else {
							// Reset ping attribute if IP is already registered
							if (array_key_exists($sIp, $this->aIPv4)) {
								if (($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'yes') ||
									($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'na')) {
									$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = 'no';
									$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
									$this->aIPv4[$sIp]['has_changed'] = 'yes';
								}
							}
							Utils::Log(LOG_DEBUG, "Ping ".$sIp." -> Not OK");
						}
					}
					$iIp += 1;
				}
				$iFinishTime = time();
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'ping_duration', (($iFinishTime - $iStartTime) == 0) ? 1 : ($iFinishTime - $iStartTime));
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'ping_discovered', $iNbIPsThatPing);
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been pinged:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs that ping: ".$iNbIPsThatPing);
			} else {
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been pinged.");
			}
		}
	}

	/**
	 * Reverse lookup all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 */
	protected function LookupIpv4Ips($sTimeStamp)
	{
		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] != 'yes') {
				continue;
			}
			if ($aIPv4Subnet['iplookup_enabled'] == 'yes') {
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);

				$iIp = $iSubnetIp + 1;
				$iNbIPsInDNS = 0;
				$iStartTime = time();
				$sDigCmd = $this->sDigPath."dig";
				Utils::Log(LOG_INFO, "Start to lookup subnet: ".$sSubnetIp);
				while ($iIp < $iBroadcastIp) {
					$sIp = long2ip($iIp);
					// Skip DHCP IP if required
					if (($aIPv4Subnet['dhcp_range_discovery_enabled'] != 'yes') && $this->IsIPInDHCPRange($iIp, $aIPv4Subnet['dhcp_ranges'])) {
						// Reset ping attribute anyway if IP is already registered
						if (array_key_exists($sIp, $this->aIPv4)) {
							if (($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'yes') ||
								($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'no')) {
								$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = 'na';
								$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = '';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						}
						Utils::Log(LOG_DEBUG, "DHCP ".$sIp." has not been looked up");
					} else {
						$bIPResolves = false;
						$aOutput = array();
						if ($this->aIPDiscoveryAttributes['dns1'] != '') {
							$LookupResult = exec($sDigCmd.' -x '.$sIp.' @'.$this->aIPDiscoveryAttributes['dns1'], $aOutput, $sStatus);
						} else {
							$LookupResult = exec($sDigCmd.' -x '.$sIp, $aOutput, $sStatus);
						}
						// Look for the "Got answer section"
						$aAnswerPosition = array_keys($aOutput, ";; Got answer:");
						if (!empty($aAnswerPosition)) {
							$iErrorIndex = $aAnswerPosition[0] + 1;
							if (strpos($aOutput[$iErrorIndex], 'NOERROR') !== false) {
								$bIPResolves = true;
							}
						} elseif ($this->aIPDiscoveryAttributes['dns2'] != '') {
							$LookupResult = exec($sDigCmd.' -x '.$sIp.' @'.$this->aIPDiscoveryAttributes['dns2'], $aOutput, $sStatus);
							// Look for the "Got answer section"
							$aAnswerPosition = array_keys($aOutput, ";; Got answer:");
							if (!empty($aAnswerPosition)) {
								$iErrorIndex = $aAnswerPosition[0] + 1;
								if (strpos($aOutput[$iErrorIndex], 'NOERROR') !== false) {
									$bIPResolves = true;
								}
							}
						}

						if ($bIPResolves) {
							// IP resolves
							// Look for the name in the "Answer" section
							$aAnswerPosition = array_keys($aOutput, ";; ANSWER SECTION:");
							if (!empty($aAnswerPosition)) {
								$iNameIndex = $aAnswerPosition[0] + 1;
								$sName = substr($aOutput[$iNameIndex], strpos($aOutput[$iNameIndex], 'PTR') + 3);
								$sName = ltrim($sName);
							} else {
								$sName = '';
							}
							if (array_key_exists($sIp, $this->aIPv4)) {
								// Change data anyway as time stamp changes
								$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = 'yes';
								$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = $sName;
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
                                if ($this->bSetStatusOnRegisteredIPs == 'yes') {
                                    $this->aIPv4[$sIp]['synchro_data']['status'] = $this->sIPDefaultStatus;
                                }
                                $this->aIPv4[$sIp]['has_changed'] = 'yes';
							} else {
								$aValues = array(
									'primary_key' => $sIp,
									'ip' => $sIp,
									'org_id' => $aIPv4Subnet['org_id'],
									'ipconfig_id' => $aIPv4Subnet['ipconfig_id'],
									'status' => $this->sIPDefaultStatus,
									'last_discovery_date' => $sTimeStamp,
									'responds_to_ping' => 'na',
									'responds_to_iplookup' => 'yes',
									'fqdn_from_iplookup' => $sName,
									'responds_to_scan' => 'na',
								);
								if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
									$aValues['view_id'] = $this->sIPDefaultView;
								}
								$this->aIPv4[$sIp]['synchro_data'] = $aValues;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
							$iNbIPsInDNS += 1;
							Utils::Log(LOG_DEBUG, "Lookup ".$sIp." -> OK : ".$sName);
						} else {
							// Reset lookup attribute if IP is already registered
							if (array_key_exists($sIp, $this->aIPv4)) {
								if (($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'yes') ||
									($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'na')) {
									$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = 'no';
									$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = '';
									$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
									$this->aIPv4[$sIp]['has_changed'] = 'yes';
								}
							}
							Utils::Log(LOG_DEBUG, "Lookup ".$sIp." -> Not OK");
						}
					}
					$iIp += 1;
				}
				$iFinishTime = time();
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'iplookup_duration', (($iFinishTime - $iStartTime) == 0) ? 1 : ($iFinishTime - $iStartTime));
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'iplookup_discovered', $iNbIPsInDNS);
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been looked up:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs in DNS: ".$iNbIPsInDNS);
			} else {
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been looked up.");
			}
		}
	}

	/**
	 * Scan all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 */
	protected function ScanIpv4Ips($sTimeStamp)
	{
		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] != 'yes') {
				continue;
			}
			if ($aIPv4Subnet['scan_enabled'] == 'yes') {
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);
				if (($this->aIPDiscoveryAttributes['scan_cnx_refused_enabled'] == 'yes') && ($aIPv4Subnet['scan_cnx_refused_enabled'] == 'yes')) {
					$bScanCnxRefusedEnabled = true;
				} else {
					$bScanCnxRefusedEnabled = false;
				}

				$iIp = $iSubnetIp + 1;
				$iScanTimeout = ($this->aIPDiscoveryAttributes['scan_timeout'] == 0) ? 1 : $this->aIPDiscoveryAttributes['scan_timeout'];
				$iNbIPsThatAnswerToScan = 0;
				$iStartTime = time();
				Utils::Log(LOG_INFO, "Start to scan subnet: ".$sSubnetIp);
				while ($iIp < $iBroadcastIp) {
					$sIp = long2ip($iIp);
					// Skip DHCP IP if required
					if (($aIPv4Subnet['dhcp_range_discovery_enabled'] != 'yes') && $this->IsIPInDHCPRange($iIp, $aIPv4Subnet['dhcp_ranges'])) {
						// Reset ping attribute anyway if IP is already registered
						if (array_key_exists($sIp, $this->aIPv4)) {
							if ($this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] != 'na') {
								$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = 'na';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						}
						Utils::Log(LOG_DEBUG, "DHCP ".$sIp." has not been scanned");
					} else {

						switch ($this->aIPDiscoveryAttributes['protocol']) {
							// Notes:
							//  - @ removes information given by fsockopen when there is a connection problem.
							//  - from PHP manual: UDP sockets will sometimes appear to have opened without an error, even if the remote
							//    host is unreachable. The error will only become apparent when you read or write data
							//    to/from the socket. The reason for this is because UDP is a "connectionless" protocol,
							//    which means that the operating system does not try to establish a link for the socket
							//    until it actually needs to send or receive data.
							case 'udp':
								$Resource = @fsockopen("udp://".$sIp, $this->aIPDiscoveryAttributes['port_number'], $errno, $errstr, floatval($iScanTimeout));
								if ($Resource) {
									socket_set_timeout($Resource, $iScanTimeout);
									$iInitialTime = time();
									fread($Resource, 26);
									fclose($Resource);
									$ScanResult = (time() >= $iInitialTime + $iScanTimeout) ? false : true;
									$errstr = "Timeout reached for UDP read";
									$errno = "N/A";
								}
								break;

							case 'tcp':
								$ScanResult = @fsockopen("tcp://".$sIp, $this->aIPDiscoveryAttributes['port_number'], $errno, $errstr, floatval($iScanTimeout));
								if ($ScanResult) {
									fclose($ScanResult);
								}
								break;

							case 'both':
							default:
							$Resource = @fsockopen("udp://".$sIp, $this->aIPDiscoveryAttributes['port_number'], $errno, $errstr, floatval($iScanTimeout));
								if ($Resource) {
									socket_set_timeout($Resource, $iScanTimeout);
									$iInitialTime = time();
									fread($Resource, 26);
									fclose($Resource);
									$ScanResult = (time() >= $iInitialTime + $iScanTimeout) ? false : true;
								}
								if (!$ScanResult) {
									$ScanResult = @fsockopen("tcp://".$sIp, $this->aIPDiscoveryAttributes['port_number'], $errno, $errstr, floatval($iScanTimeout));
									if ($ScanResult) {
										fclose($ScanResult);
									}
								}
								break;

						}
						if (!$ScanResult) {
							// IP doesn't answer to scan.
							// Check errno:
							//  111 -> connection is refused: the CI may be alive but not able or willing to answer on that port. A firewall may be blocking the traffic too...
							//  110 -> connection time out: we can assume that no CI sits behind the IP
							// Reset scan attribute if IP is already registered
							if (array_key_exists($sIp, $this->aIPv4)) {
								// Change data anyway as time stamp changes
								if (($errno == 111) && ($bScanCnxRefusedEnabled)) {
									$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] = 'cnx_refused';
								} else {
									$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] = 'no';
								}
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							} else {
								// Create IP if cnx_refused
								if (($errno == 111) && ($bScanCnxRefusedEnabled)) {
									$aValues = array(
										'primary_key' => $sIp,
										'ip' => $sIp,
										'org_id' => $aIPv4Subnet['org_id'],
										'ipconfig_id' => $aIPv4Subnet['ipconfig_id'],
										'status' => $this->sIPDefaultStatus,
										'last_discovery_date' => $sTimeStamp,
										'responds_to_ping' => 'na',
										'responds_to_iplookup' => 'na',
										'fqdn_from_iplookup' => '',
										'responds_to_scan' => 'cnx_refused',
									);
									if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
										$aValues['view_id'] = $this->sIPDefaultView;
									}
									$this->aIPv4[$sIp]['synchro_data'] = $aValues;
									$this->aIPv4[$sIp]['has_changed'] = 'yes';
								}
							}
							Utils::Log(LOG_DEBUG, "Scan ".$sIp." -> Not OK: ".$errstr."(".$errno.")");
						} else {
							// IP answers to scan
							if (array_key_exists($sIp, $this->aIPv4)) {
                                // Change data anyway as time stamp changes
								$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] = 'yes';
                                $this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
                                if ($this->bSetStatusOnRegisteredIPs == 'yes') {
                                    $this->aIPv4[$sIp]['synchro_data']['status'] = $this->sIPDefaultStatus;
                                }
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							} else {
								$aValues = array(
									'primary_key' => $sIp,
									'ip' => $sIp,
									'org_id' => $aIPv4Subnet['org_id'],
									'ipconfig_id' => $aIPv4Subnet['ipconfig_id'],
									'status' => $this->sIPDefaultStatus,
									'last_discovery_date' => $sTimeStamp,
									'responds_to_ping' => 'na',
									'responds_to_iplookup' => 'na',
									'fqdn_from_iplookup' => '',
									'responds_to_scan' => 'yes',
								);
								if ($this->oCollectionPlan->IsTeemIpZoneMgmtInstalled()) {
									$aValues['view_id'] = $this->sIPDefaultView;
								}
								$this->aIPv4[$sIp]['synchro_data'] = $aValues;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
							$iNbIPsThatAnswerToScan += 1;
							Utils::Log(LOG_DEBUG, "Scan ".$sIp." -> OK");
						}
					}
					$iIp += 1;
				}
				$iFinishTime = time();
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'scan_duration', (($iFinishTime - $iStartTime) == 0) ? 1 : ($iFinishTime - $iStartTime));
				$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'scan_discovered', $iNbIPsThatAnswerToScan);
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been scanned:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs that have been scanned: ".$iNbIPsThatAnswerToScan);
			} else {
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been scanned.");
			}
		}
	}

	/**
	 * @inheritdoc
	 */
	public function Prepare()
	{
		$bRet = parent::Prepare();
		if (!$bRet) {
			return false;
		}
		
		// check list of ubnets to discover
		if (empty($this->aIPv4SubnetsList)) {
			// Just exit if there are no subnet to scan.
			Utils::Log(LOG_INFO, "There is no subnet to discover with the IP Discovery application ".$this->oCollectionPlan->GetApplicationParam('UUID').".");

			return true;
		}

		// Make sure that discovery is not deactivated on all subnets
		$bAtLeastsOnSubnetToDiscover = false;
		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
				$bAtLeastsOnSubnetToDiscover = true;
				break;
			}
		}
		if (!$bAtLeastsOnSubnetToDiscover) {
			// Just exit if there are no subnet to scan.
			Utils::Log(LOG_INFO, "All subnets attached to the IP Discovery application ".$this->oCollectionPlan->GetApplicationParam('UUID')." have deactivated IP discovery.");

			return true;
		}

		// List the already registered IPs
		$this->GetRegisteredIps();

		// Time stamp discovery
		$iStartTime = time();
		$sTimeStamp = date('Y-m-d H:i:s', $iStartTime);
		foreach ($this->aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			$this->oCollectionPlan->SetSubnetParam($sSubnetIp, 'last_discovery_date', $sTimeStamp);
		}


		// Ping IPs
		if ($this->aIPDiscoveryAttributes['ping_enabled'] == 'yes') {
			$this->PingIpv4Ips($sTimeStamp);
		}

		// Lookup IPs
		if ($this->aIPDiscoveryAttributes['iplookup_enabled'] == 'yes') {
			$this->LookupIpv4Ips($sTimeStamp);
		}

		// Scan IPs
		if ($this->aIPDiscoveryAttributes['scan_enabled'] == 'yes') {
			$this->ScanIpv4Ips($sTimeStamp);
		}

		// Re-index array
		//$this->aIPv4 = array_values($this->aIPv4);
		// Filter IPs which status has not changed
		$aFinalIPv4 = array();
		foreach ($this->aIPv4 as $sIp => $aValue) {
			if ($aValue['has_changed'] == 'yes') {
				$aFinalIPv4[] = $aValue['synchro_data'];
			}
		}
		$this->aIPv4 = $aFinalIPv4;

		// Time stamp IP Discovery application
		$iFinishTime = time();
		$this->oCollectionPlan->SetApplicationParam('last_discovery_date', $sTimeStamp);
		$this->oCollectionPlan->SetApplicationParam('duration', $iFinishTime - $iStartTime);

		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function Collect($iMaxChunkSize = 0): bool
	{
		Utils::Log(LOG_INFO, '----------------');

		return parent::Collect($iMaxChunkSize);
	}

	/**
	 * @inheritdoc
	 */
	public function Synchronize($iMaxChunkSize = 0): bool
	{
		Utils::Log(LOG_INFO, '----------------');

		return parent::Synchronize($iMaxChunkSize);
	}

	/**
	 * @inheritdoc
	 */
	protected function InitProcessBeforeSynchro(): void
	{
		// Create IPConfig mapping table
		$this->oIPv4AddressIPConfigMapping = new LookupTable('SELECT IPConfig', array('org_id_friendlyname'));
	}

	/**
	 * @inheritdoc
	 */
	protected function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex)
	{
		if (!$this->oIPv4AddressIPConfigMapping->Lookup($aLineData, array('org_id'), 'ipconfig_id', $iLineIndex)) {
			throw new IgnoredRowException('Unknown IP Config');
		}
	}

	/**
	 * @inheritdoc
	 */
	public function fetch()
	{
		if ($this->iIndex < count($this->aIPv4)) {
			$aDatas = $this->aIPv4[$this->iIndex];
			$this->iIndex++;

			return $aDatas;
		}

		return false;
	}

}
