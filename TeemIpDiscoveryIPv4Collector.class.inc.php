<?php
// Copyright (C) 2014 Combodo SARL
//
//   This application is free software; you can redistribute it and/or modify	
//   it under the terms of the GNU Affero General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   iTop is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU Affero General Public License for more details.
//
//   You should have received a copy of the GNU Affero General Public License
//   along with this application. If not, see <http://www.gnu.org/licenses/>

class TeemIpDiscoveryIPv4Collector extends Collector
{
	protected $iIndex;
	protected $sDiscoveryApplicationUUID;
	protected $sPingEnabled;
	protected $iPingTimeout;
	protected $sIplookupEnabled;
	protected $sDNS1;
	protected $sDNS2;
	protected $sScanEnabled;
	protected $iPortNumber;
	protected $sProtocol;
	protected $iScanTimeout;
	protected $sIPDefaultOrgId;
	protected $sIPDefaultStatus;
	static protected $aIPv4SubnetsList;
	protected $sPingPath;
	protected $sDigPath;
	protected $aIPv4;	
	
	public function __construct()
	{
		parent::__construct();
		
		$this->iIndex = 0;
		$aOtherPlaceholders = Utils::GetConfigurationValue('json_placeholders', array());
		if (array_key_exists('discovery_application_uuid', $aOtherPlaceholders))
		{
			$this->sDiscoveryApplicationUUID = $aOtherPlaceholders['discovery_application_uuid'];
		}
		else
		{
			$this->sDiscoveryApplicationUUID = '';
		}
		$this->sIPDefaultOrgId  = Utils::GetConfigurationValue('ip_default_org_id', 'Demo');
		$this->sIPDefaultStatus = Utils::GetConfigurationValue('ip_default_status','unassigned');
		$this->sPingPath = Utils::GetConfigurationValue('ping_absolute_path','');
		$this->sDigPath = Utils::GetConfigurationValue('dig_absolute_path','');
		self::$aIPv4SubnetsList   = array();
		
		$this->aIPv4 = array();
	}

	protected function GetDelayAsString($iStart, $iStop)
	{
		$iDelay = $iStop -$iStart;
		$iHours = intval($iDelay / 3600);
		$iMinutes = intval(($iDelay - ($iHours * 3600)) / 60);
		$iSeconds = $iDelay - ($iHours * 3600) - ($iMinutes * 60);
		
		$sDelay = $iHours." hours, ".$iMinutes." minutes, ".$iSeconds." seconds";
		return $sDelay;
	}
	
	/*
	 * Retrieve the IP Discovery object from iTop based on given UUID
	 * Read discovery parameters and list of subnets to be discovered
	 */
	protected function GetDiscoveryParameters()
	{
		$bResult = true;
		try
		{
			$oRestClient = new RestClient();
			$aResult = $oRestClient->Get('IPDiscovery', array('uuid' => $this->sDiscoveryApplicationUUID));
			if ($aResult['code'] != 0)
			{
				Utils::Log(LOG_ERR, "{$aResult['message']} ({$aResult['code']})");
				$bResult = false;
			}
			else 
			{
				switch(count($aResult['objects']))
				{
					case 0:
						// not found, error
						Utils::Log(LOG_INFO, "There is no IP Discovery Application with UUID ".$this->sDiscoveryApplicationUUID." in iTop.");
						$bResult = false;
					break;
					
					case 1:
						foreach($aResult['objects'] as $sKey => $aData)
						{
							$aData = reset($aResult['objects']);
							$aIPDiscoveryAttributes = $aData['fields'];
							
							$this->sPingEnabled 	= $aIPDiscoveryAttributes['ping_enabled'];
							$this->iPingTimeout 	= $aIPDiscoveryAttributes['ping_timeout'];
							$this->sIplookupEnabled	= $aIPDiscoveryAttributes['iplookup_enabled'];
							$this->sDNS1 			= $aIPDiscoveryAttributes['dns1'];
							$this->sDNS2 			= $aIPDiscoveryAttributes['dns2'];
							$this->sScanEnabled 	= $aIPDiscoveryAttributes['scan_enabled'];
							$this->iPortNumber 		= $aIPDiscoveryAttributes['port_number'];
							$this->sProtocol		= $aIPDiscoveryAttributes['protocol'];
							$this->iScanTimeout		= $aIPDiscoveryAttributes['scan_timeout'];
							foreach ($aIPDiscoveryAttributes['ipv4subnets_list'] as $sSubnetKey => $aIPv4Subnet)
							{
								$sIndex = $aIPv4Subnet['ip'];
								self::$aIPv4SubnetsList[$sIndex]['org_id'] 				= $aIPv4Subnet['org_id'];
								self::$aIPv4SubnetsList[$sIndex]['mask'] 				= $aIPv4Subnet['mask'];
								self::$aIPv4SubnetsList[$sIndex]['gatewayip'] 			= $aIPv4Subnet['gatewayip'];
								self::$aIPv4SubnetsList[$sIndex]['broadcastip'] 		= $aIPv4Subnet['broadcastip'];
								self::$aIPv4SubnetsList[$sIndex]['ping_enabled'] 		= $aIPv4Subnet['ping_enabled'];
								self::$aIPv4SubnetsList[$sIndex]['ping_duration'] 		= 0;
								self::$aIPv4SubnetsList[$sIndex]['iplookup_enabled']	= $aIPv4Subnet['iplookup_enabled'];
								self::$aIPv4SubnetsList[$sIndex]['iplookup_duration'] 	= 0;
								self::$aIPv4SubnetsList[$sIndex]['scan_enabled'] 		= $aIPv4Subnet['scan_enabled'];
								self::$aIPv4SubnetsList[$sIndex]['scan_duration'] 		= 0;
							}
								
							Utils::Log(LOG_INFO, "---------- IP Discovery Parameters ----------");
							Utils::Log(LOG_INFO, "Ping enabled: ".$this->sPingEnabled);
							Utils::Log(LOG_INFO, "Ping timeout: ".$this->iPingTimeout);
							Utils::Log(LOG_INFO, "NsLookup enabled: ".$this->sIplookupEnabled);
							Utils::Log(LOG_INFO, "DNS #1: ".$this->sDNS1);
							Utils::Log(LOG_INFO, "DNS #2: ".$this->sDNS2);
							Utils::Log(LOG_INFO, "Scan enabled: ".$this->sScanEnabled);
							Utils::Log(LOG_INFO, "Port number: ".$this->iPortNumber);
							Utils::Log(LOG_INFO, "Protocol: ".$this->sProtocol);
							Utils::Log(LOG_INFO, "Scan timeout: ".$this->iScanTimeout);
							Utils::Log(LOG_INFO, "---------- List of subnets to discover ----------");
							foreach (self::$aIPv4SubnetsList as $sIp => $aIPv4Subnet)
							{
								Utils::Log(LOG_INFO, "Subnet: ".$sIp." / ".$aIPv4Subnet['mask']);
								Utils::Log(LOG_DEBUG, "     Ping enabled: ".$aIPv4Subnet['ping_enabled']);
								Utils::Log(LOG_DEBUG, "     Iplookup enabled: ".$aIPv4Subnet['iplookup_enabled']);
								Utils::Log(LOG_DEBUG, "     Scan enabled: ".$aIPv4Subnet['scan_enabled']);
							}
							Utils::Log(LOG_INFO, "---------------------------------------------");
						}					
						$bResult = true;
					break;
					
					default:
						// Ambiguous !!
						Utils::Log(LOG_ERR, "There are ".count($aResult['objects'])." IP Discovery Applications with UUID ".$this->sDiscoveryApplicationUUID." in iTop. Cannot continue.");
						$bResult = false;
				}
			}
		}
		catch(Exception $e)
		{
			Utils::Log(LOG_ERR, $e->getMessage());
			$bResult = false;
		}
		return $bResult;
	}

	/*
	 * Retrieve the list of all IPs already registered
	 */
	protected function GetRegisteredIps()
	{
		// Build OQL to retrieve IPs
		$bStart = true;
		$sOQL = '';
		foreach (self::$aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			if ($bStart)
			{
				$sOQL = "SELECT IPv4Address WHERE subnet_ip IN ('".$sSubnetIp."'";
				$bStart = false;
			}
			else
			{
				$sOQL .= ", '".$sSubnetIp."'";
			}			
		}
		$sOQL .= ")";
		
		// Get IPs
		$bResult = true;
		try
		{
			$oRestClient = new RestClient();
			$aResult = $oRestClient->Get('IPv4Address', $sOQL, 'ip, org_id, status, responds_to_ping, responds_to_iplookup, responds_to_scan');
			if ($aResult['code'] != 0)
			{
				Utils::Log(LOG_ERR, "{$aResult['message']} ({$aResult['code']})");
				$bResult = false;
			}
			else 
			{
				if (!empty($aResult['objects']))
				{
					Utils::Log(LOG_DEBUG, "---------- List of IPs already registered ----------");
					Utils::Log(LOG_DEBUG, "OQL: ".$sOQL);
					foreach($aResult['objects'] as $sKey => $aData)
					{
						$aIPAttributes = $aData['fields'];
						$sIp = $aIPAttributes['ip'];
						$this->aIPv4[$sIp]['synchro_data']['primary_key'] 			= $sIp;
						$this->aIPv4[$sIp]['synchro_data']['ip']           			= $sIp;
						$this->aIPv4[$sIp]['synchro_data']['org_id']				= $aIPAttributes['org_id'];
						$this->aIPv4[$sIp]['synchro_data']['status']				= $aIPAttributes['status'];
						$this->aIPv4[$sIp]['synchro_data']['responds_to_ping']		= $aIPAttributes['responds_to_ping'];
						$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup']	= $aIPAttributes['responds_to_iplookup'];
						$this->aIPv4[$sIp]['synchro_data']['responds_to_scan']		= $aIPAttributes['responds_to_scan'];
						$this->aIPv4[$sIp]['has_changed'] = false;
									
						Utils::Log(LOG_DEBUG, "IP: ".$sIp);
					}
				}
				Utils::Log(LOG_DEBUG, "---------------------------------------------");
			}					
		}
		catch(Exception $e)
		{
			Utils::Log(LOG_ERR, $e->getMessage());
			$bResult = false;
		}
		return $bResult;
	}
	
	/*
	 * Ping all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 */
	protected function PingIpv4Ips($sTimeStamp)
	{
		foreach (self::$aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			if ($aIPv4Subnet['ping_enabled'] == 'yes')
			{
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);
				
				$iIp = $iSubnetIp + 1;					
				$iTimeOut = ($this->iPingTimeout == 0) ? 1 : $this->iPingTimeout;
				$iNbIPsThatPing = 0;
				$iStartTime = time();
				$sPingCmd = $this->sPingPath."ping";
				Utils::Log(LOG_INFO, "Start to ping subnet: ".$sSubnetIp);
				while ($iIp < $iBroadcastIp)
				{
					$sIp = long2ip($iIp);
					$aOutput = array();
					$PingResult = exec("$sPingCmd -c1 -w$iTimeOut $sIp", $aOutput, $sStatus);
				    if ($sStatus == 0)
				    {
				    	// IP is alive
				    	if (array_key_exists($sIp, $this->aIPv4))
						{
							// Change data anyway as time stamp changes
							$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] ='yes';
							$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
						}
						else
						{
							$aValues = array(
								'primary_key'			=> $sIp,
								'ip'           			=> $sIp,
								'org_id'				=> $aIPv4Subnet['org_id'],
								'status'				=> $this->sIPDefaultStatus,
								'last_discovery_date'   => $sTimeStamp,
								'responds_to_ping'		=> 'yes',
								'responds_to_iplookup'	=> 'na',
								'fqdn_from_iplookup'	=> '',
								'responds_to_scan'		=> 'na',
							);
							$this->aIPv4[$sIp]['synchro_data'] = $aValues;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
						}
						$iNbIPsThatPing += 1;
						Utils::Log(LOG_DEBUG, "Ping ".$sIp." -> OK");
				    }
				    else
				    {
				    	// Reset ping attribute if IP is already registered
				    	if (array_key_exists($sIp, $this->aIPv4))
						{
							if (($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'yes') ||
								($this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] == 'na'))
							{
								$this->aIPv4[$sIp]['synchro_data']['responds_to_ping'] = 'no';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						}
				    	Utils::Log(LOG_DEBUG, "Ping ".$sIp." -> Not OK");
				    }
				    $iIp += 1;
				}
				$iFinishTime = time();
				self::$aIPv4SubnetsList[$sSubnetIp]['ping_duration'] = $iFinishTime - $iStartTime;
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been pinged:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs that ping: ".$iNbIPsThatPing);
			}
			else
			{
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been pinged.");
			}
		}
	}
	
	/*
	 * Reverse lookup all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 */
	protected function LookupIpv4Ips($sTimeStamp)
	{
		foreach (self::$aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			if ($aIPv4Subnet['iplookup_enabled'] == 'yes')
			{
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);
				
				$iIp = $iSubnetIp + 1;
				$iNbIPsInDNS = 0;
				$iStartTime = time();
				$sDigCmd = $this->sDigPath."dig";
				Utils::Log(LOG_INFO, "Start to lookup subnet: ".$sSubnetIp);
				while ($iIp < $iBroadcastIp)
				{
					$sIp = long2ip($iIp);
					$bIPResolves = false;
					$aOutput = array();
					if ($this->sDNS1 != '')
					{
						$LookupResult = exec("$sDigCmd -x $sIp @$this->sDNS1", $aOutput, $sStatus);
					}
					else
					{
						$LookupResult = exec("dig -x $sIp", $aOutput, $sStatus);
					}
					// Look for the "Got answer section"
					$aAnswerPosition = array_keys($aOutput, ";; Got answer:");
					if (!empty($aAnswerPosition))
					{
						$iErrorIndex = $aAnswerPosition[0] + 1;
						if (strpos($aOutput[$iErrorIndex], 'NOERROR') !== FALSE)
						{
							$bIPResolves = true;
						}
					}
					elseif ($this->sDNS2 != '')
					{
						$LookupResult = exec("dig -x $sIp @$this->sDNS2", $aOutput, $sStatus);
						// Look for the "Got answer section"
						$aAnswerPosition = array_keys($aOutput, ";; Got answer:");
						if (!empty($aAnswerPosition))
						{
							$iErrorIndex = $aAnswerPosition[0] + 1;
							if (strpos($aOutput[$iErrorIndex], 'NOERROR') !== FALSE)
							{
								$bIPResolves = true;
							}
						}
					}
						
					if ($bIPResolves)
					{
						// IP resolves
						// Look for the name in the "Answer" section
 						$aAnswerPosition = array_keys($aOutput, ";; ANSWER SECTION:");
						if (!empty($aAnswerPosition))
						{
							$iNameIndex = $aAnswerPosition[0] + 1;
							$sName = substr($aOutput[$iNameIndex], strpos($aOutput[$iNameIndex], 'PTR') + 3);
							$sName = ltrim($sName);
						}
						else
						{
							$sName = '';
						}
						if (array_key_exists($sIp, $this->aIPv4))
						{
							// Change data anyway as time stamp changes
							$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = 'yes';
							$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = $sName;
							$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
						}
						else
						{
							$aValues = array(
								'primary_key'			=> $sIp,
								'ip'           			=> $sIp,
								'org_id'				=> $aIPv4Subnet['org_id'],
								'status'				=> $this->sIPDefaultStatus,
								'last_discovery_date'   => $sTimeStamp,
								'responds_to_ping'		=> 'na',
								'responds_to_iplookup'	=> 'yes',
								'fqdn_from_iplookup'	=> $sName,
								'responds_to_scan'		=> 'na',
							);
							$this->aIPv4[$sIp]['synchro_data'] = $aValues;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						$iNbIPsInDNS += 1;
						Utils::Log(LOG_DEBUG, "Lookup ".$sIp." -> OK");
					}
					else
					{
				    	// Reset lookup attribute if IP is already registered
						if (array_key_exists($sIp, $this->aIPv4))
						{
							if (($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'yes') ||
								($this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] == 'na'))
							{
								$this->aIPv4[$sIp]['synchro_data']['responds_to_iplookup'] = 'no';
								$this->aIPv4[$sIp]['synchro_data']['fqdn_from_iplookup'] = '';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
							}
						}
						Utils::Log(LOG_DEBUG, "Lookup ".$sIp." -> Not OK");
					}
					$iIp += 1;
				}
				$iFinishTime = time();
				self::$aIPv4SubnetsList[$sSubnetIp]['iplookup_duration'] = $iFinishTime - $iStartTime;
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been looked up:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs in DNS: ".$iNbIPsInDNS);
			}
			else
			{
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been looked up.");
			}
		}
	}
	
	/*
	 * Scan all IPs of IPv4 subnets defined in IP Discovery application
	 *   ... unless specified otherwise at subnet level.
	 */
	protected function ScanIpv4Ips($sTimeStamp)
	{
		foreach (self::$aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			if ($aIPv4Subnet['scan_enabled'] == 'yes')
			{
				$iSubnetIp = ip2long($sSubnetIp);
				$iBroadcastIp = ip2long($aIPv4Subnet['broadcastip']);
				
				$iIp = $iSubnetIp + 1;
				$iScanTimeout = ($this->iScanTimeout == 0) ? 1 : $this->iScanTimeout;
				$iNbIPsThatAnswerToScan = 0;
				$iStartTime = time();
				Utils::Log(LOG_INFO, "Start to scan subnet: ".$sSubnetIp);
				while ($iIp < $iBroadcastIp)
				{
					$sIp = long2ip($iIp);
				
					switch($this->sProtocol)
					{
						// Notes:
						//  - @ removes information given by fsockopen when there is a connection problem.
						//  - from PHP manual: UDP sockets will sometimes appear to have opened without an error, even if the remote
						//    host is unreachable. The error will only become apparent when you read or write data 
						//    to/from the socket. The reason for this is because UDP is a "connectionless" protocol, 
						//    which means that the operating system does not try to establish a link for the socket 
						//    until it actually needs to send or receive data. 
						case 'udp':
							$Resource = @fsockopen("udp://".$sIp, $this->iPortNumber, $errno, $errstr, $iScanTimeout);
							if ($Resource)
							{
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
							$ScanResult = @fsockopen("tcp://".$sIp, $this->iPortNumber, $errno, $errstr, $iScanTimeout);
							if ($ScanResult)
							{
								fclose($ScanResult);
							}
						break;
						
						case 'both':
						default:
							$Resource = @fsockopen("udp://".$sIp, $this->iPortNumber, $errno, $errstr, $iScanTimeout);
							if ($Resource)
							{
								socket_set_timeout($Resource, $iScanTimeout);
								$iInitialTime = time();
								fread($Resource, 26);
								fclose($Resource);
								$ScanResult = (time() >= $iInitialTime + $iScanTimeout) ? false : true;
							}
							if (!$ScanResult)
							{
								$ScanResult = @fsockopen("tcp://".$sIp, $this->iPortNumber, $errno, $errstr, $iScanTimeout);
								if ($ScanResult)
								{
									fclose($ScanResult);
								}
							}
						break;
						
					}
					if (!$ScanResult)
					{
						// IP doesn't answer to scan.
						// Reset scan attribute if IP is already registered
						if (array_key_exists($sIp, $this->aIPv4))
						{
							// Change data anyway as time stamp changes
							$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] = 'no';
							$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
						}
						Utils::Log(LOG_DEBUG, "Scan ".$sIp." -> Not OK: ".$errstr ."(".$errno.")");
					}
					else
					{
						// IP answers to scan
				    	if (array_key_exists($sIp, $this->aIPv4))
						{
							if (($this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] == 'no') ||
								($this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] == 'na'))
							{
								$this->aIPv4[$sIp]['synchro_data']['responds_to_scan'] ='yes';
								$this->aIPv4[$sIp]['has_changed'] = 'yes';
								$this->aIPv4[$sIp]['synchro_data']['last_discovery_date'] = $sTimeStamp;
							}
						}
						else
						{
							$aValues = array(
								'primary_key'			=> $sIp,
								'ip'           			=> $sIp,
								'org_id'				=> $aIPv4Subnet['org_id'],
								'status'				=> $this->sIPDefaultStatus,
								'last_discovery_date'   => $sTimeStamp,
								'responds_to_ping'		=> 'na',
								'responds_to_iplookup'	=> 'na',
								'fqdn_from_iplookup'	=> '',
								'responds_to_scan'		=> 'yes',
							);
							$this->aIPv4[$sIp]['synchro_data'] = $aValues;
							$this->aIPv4[$sIp]['has_changed'] = 'yes';
						}
						$iNbIPsThatAnswerToScan += 1;
						Utils::Log(LOG_DEBUG, "Scan ".$sIp." -> OK");
					}
				    $iIp += 1;
				}
				$iFinishTime = time();
				self::$aIPv4SubnetsList[$sSubnetIp]['scan_duration'] = $iFinishTime - $iStartTime;
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has been scanned:");
				Utils::Log(LOG_DEBUG, "      - Duration: ".$this->GetDelayAsString($iStartTime, $iFinishTime));
				Utils::Log(LOG_DEBUG, "      - Number of IPs that have been scanned: ".$iNbIPsThatAnswerToScan);
			}
			else
			{
				Utils::Log(LOG_INFO, "Subnet: ".$sSubnetIp." has not been scanned.");
			}
		}
	}

	public static function GetUpdatedSubnetList()
	{
		return self::$aIPv4SubnetsList;
	}

	public function prepare()
	{
		// Get parameters of IP Discovery Application
		if (!$this->GetDiscoveryParameters())
		{
			return false;
		}
		if (empty(self::$aIPv4SubnetsList))
		{
			// Just exit if there are no subnet to scan.
			Utils::Log(LOG_INFO, "There is no subnet to discover with the IP Discovery application ".$this->sDiscoveryApplicationUUID.".");
			return true;
		}
		
		// Get list of already registered IPs
		$this->GetRegisteredIps();

		// Time stamp discovery
		$sTimeStamp = date('Y-m-d H:i:s', time());
		foreach (self::$aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			self::$aIPv4SubnetsList[$sSubnetIp]['last_discovery_date'] = $sTimeStamp;
		}


		// Ping IPs
		if ($this->sPingEnabled == 'yes')
		{
			$this->PingIpv4Ips($sTimeStamp);
		}
		
		// Lookup IPs
		if ($this->sIplookupEnabled == 'yes')
		{
			$this->LookupIpv4Ips($sTimeStamp);
		}
		
		// Scan IPs
		if ($this->sScanEnabled == 'yes')
		{
			$this->ScanIpv4Ips($sTimeStamp);
		}
		
		// Re-index array
		//$this->aIPv4 = array_values($this->aIPv4);
		// Filter IPs which status has not changed
		$aFinalIPv4 = array();
		foreach($this->aIPv4 as $sIp => $aValue)
		{
			if ($aValue['has_changed'] == true)
			{
				$aFinalIPv4[] = $aValue['synchro_data'];
			}
		}
		$this->aIPv4 = $aFinalIPv4;
		return true;
	}

	public function fetch()
	{
		if ($this->iIndex < count($this->aIPv4))
		{
			$aDatas = $this->aIPv4[$this->iIndex];
			$this->iIndex++;

			return $aDatas;
		}
		return false;
	}

}
