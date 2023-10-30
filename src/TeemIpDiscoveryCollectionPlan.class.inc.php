<?php
/*
 * @copyright   Copyright (C) 2023 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

require_once(APPROOT.'core/collectionplan.class.inc.php');

class TeemIpDiscoveryCollectionPlan extends CollectionPlan
{
	private $bTeemIpIsInstalled;
	private $bTeemIpIpDiscoveryIsInstalled;
	private $bTeemIpNMEIsInstalled;
	private $bTeemIpZoneMgmtIsInstalled;
	private $bTeemIpIPRequestMgmtIsInstalled;
	private $aDiscoveryApplication;
	private $aIPv4SubnetsList;

	/**
	 * @inheritdoc
	 */
	public function Init(): void
	{
		parent::Init();

		// Make sure TeemIp is installed
		Utils::Log(LOG_INFO, '---------- Check TeemIp installation ----------');
		$this->bTeemIpIsInstalled = false;
		$this->bTeemIpIpDiscoveryIsInstalled = false;
		$this->bTeemIpNMEIsInstalled = false;
		$this->bTeemIpZoneMgmtIsInstalled = false;
		$this->bTeemIpIPRequestMgmtIsInstalled = false;
		$oRestClient = new RestClient();
		try {
			$aResult = $oRestClient->Get('IPAddress', 'SELECT IPAddress WHERE id = 0');
			if ($aResult['code'] == 0) {
				$this->bTeemIpIsInstalled = true;
				Utils::Log(LOG_INFO, 'TeemIp is installed');
			} else {
				Utils::Log(LOG_INFO, $sMessage = 'TeemIp is NOT installed');
			}
		} catch (Exception $e) {
			$sMessage = 'TeemIp is considered as NOT installed due to: '.$e->getMessage();
			if (is_a($e, "IOException")) {
				Utils::Log(LOG_ERR, $sMessage);
				throw $e;
			}
		}

		if ($this->bTeemIpIsInstalled) {
			// Check if TeemIp IpDiscovery is installed or not
			$oRestClient = new RestClient();
			try {
				$aResult = $oRestClient->Get('IPDiscovery', 'SELECT IPDiscovery WHERE id = 0');
				if ($aResult['code'] == 0) {
					$this->bTeemIpIpDiscoveryIsInstalled = true;
					Utils::Log(LOG_INFO, 'TeemIp IP Discovery is installed');
				} else {
					Utils::Log(LOG_INFO, 'TeemIp IP Discovery is NOT installed');
				}
			} catch (Exception $e) {
				$sMessage = 'TeemIp IP Discovery is considered as NOT installed due to: '.$e->getMessage();
				if (is_a($e, "IOException")) {
					Utils::Log(LOG_ERR, $sMessage);
					throw $e;
				}
			}

			// Check if TeemIp Network Management Extended is installed or not
			$oRestClient = new RestClient();
			try {
				$aResult = $oRestClient->Get('InterfaceSpeed', 'SELECT InterfaceSpeed WHERE id = 0');
				if ($aResult['code'] == 0) {
					$this->bTeemIpNMEIsInstalled = true;
					Utils::Log(LOG_INFO, 'TeemIp Network Management Extended is installed');
				} else {
					Utils::Log(LOG_INFO, 'TeemIp Network Management Extended is NOT installed');
				}
			} catch (Exception $e) {
				$sMessage = 'TeemIp Network Management Extended is considered as NOT installed due to: '.$e->getMessage();
				if (is_a($e, "IOException")) {
					Utils::Log(LOG_ERR, $sMessage);
					throw $e;
				}
			}

			// Check if TeemIp Zone Mgmt is installed or not
			$oRestClient = new RestClient();
			try {
				$aResult = $oRestClient->Get('Zone', 'SELECT Zone WHERE id = 0');
				if ($aResult['code'] == 0) {
					$this->bTeemIpZoneMgmtIsInstalled = true;
					Utils::Log(LOG_INFO, 'TeemIp Zone Management extension is installed');
				} else {
					Utils::Log(LOG_INFO, 'TeemIp Zone Management extension is NOT installed');
				}
			} catch (Exception $e) {
				$sMessage = 'TeemIp Zone Management is considered as NOT installed due to: '.$e->getMessage();
				if (is_a($e, "IOException")) {
					Utils::Log(LOG_ERR, $sMessage);
					throw $e;
				}
			}

			// Check if TeemIp IP Request Mgmt is installed or not
			$oRestClient = new RestClient();
			try {
				$aResult = $oRestClient->Get('IPRequest', 'SELECT IPRequest WHERE id = 0');
				if ($aResult['code'] == 0) {
					$this->bTeemIpIPRequestMgmtIsInstalled = true;
					Utils::Log(LOG_INFO, 'TeemIp IP Request Management extension is installed');
				} else {
					Utils::Log(LOG_INFO, 'TeemIp IP Request Management extension is NOT installed');
				}
			} catch (Exception $e) {
				$sMessage = 'TeemIp IP Request Management is considered as NOT installed due to: '.$e->getMessage();
				if (is_a($e, "IOException")) {
					Utils::Log(LOG_ERR, $sMessage);
					throw $e;
				}
			}

			// Get Discovery application UUID
			$aOtherPlaceholders = Utils::GetConfigurationValue('json_placeholders', []);
			if (array_key_exists('discovery_application_uuid', $aOtherPlaceholders) && !empty($aOtherPlaceholders['discovery_application_uuid'])) {
				$this->aDiscoveryApplication['UUID'] = $aOtherPlaceholders['discovery_application_uuid'];
				Utils::Log(LOG_INFO, "Requested IP Discovery Application's UUID is ".$this->aDiscoveryApplication['UUID'].".");
			} else {
				$this->aDiscoveryApplication['UUID'] = '';
				Utils::Log(LOG_ERR, "Discovery can not proceed as no IP Discovery Application UUID has been defined.");
			}

			// Get discovery parameters
			if ($this->aDiscoveryApplication['UUID'] != '') {
				list($bResult, $this->aDiscoveryApplication['params'], $this->aIPv4SubnetsList) = $this->GetDiscoveryParameters($this->aDiscoveryApplication['UUID']);
				if (!$bResult) {
					Utils::Log(LOG_ERR, "It has not been possible to retrieve working parameters. Discovery process must stop here !");
				}
			}
		}

	}

	/**
	 * No collectors are added if no application parameters could be found.
	 * @inheritDoc
	 */
	public function AddCollectorsToOrchestrator(): bool
	{
		if (empty($this->aDiscoveryApplication['UUID']) || empty($this->aDiscoveryApplication['params'])) return false;

		return parent::AddCollectorsToOrchestrator();
	}

	/**
	 * Retrieve the IP Discovery object from iTop based on given UUID
	 * Read discovery parameters and list of subnets to be discovered
	 *
	 * @return bool
	 * @throws \Exception
	 */
	protected function GetDiscoveryParameters($sApplicationUUID): array
	{
		$aIPDiscoveryAttributes = [];
		$aIPv4SubnetsList = [];
		$bResult = true;
		try {
			$oRestClient = new RestClient();
			$aResult = $oRestClient->Get('IPDiscovery', array('uuid' => $sApplicationUUID));
			if ($aResult['code'] != 0) {
				Utils::Log(LOG_ERR, "{$aResult['message']} ({$aResult['code']})");
				$bResult = false;
			} else {
				if (empty($aResult['objects'])) {
					// Not found, error
					Utils::Log(LOG_WARNING, "There is no IP Discovery Application with UUID ".$sApplicationUUID." in iTop.");
					$bResult = false;
				} else switch (count($aResult['objects'])) {
					case 1:
						Utils::Log(LOG_INFO, "An IP Discovery Application with UUID ".$sApplicationUUID." has been found in iTop.");
						$aData = reset($aResult['objects']);
						$aIPDiscoveryAttributes = $aData['fields'];
						$aIPDiscoveryAttributes['id'] = (int) $aData['key'];

						foreach ($aIPDiscoveryAttributes['ipv4subnets_list'] as $aIPv4Subnet) {
							$sIndex = $aIPv4Subnet['ip'];
							if (array_key_exists('ipdiscovery_enabled', $aIPv4Subnet)) {
								$aIPv4SubnetsList[$sIndex]['ipdiscovery_enabled'] = $aIPv4Subnet['ipdiscovery_enabled'];
							} else {
								$aIPv4SubnetsList[$sIndex]['ipdiscovery_enabled'] = 'yes';
							}
							$aIPv4SubnetsList[$sIndex]['org_id'] = $aIPv4Subnet['org_id'];
							$aIPv4SubnetsList[$sIndex]['mask'] = $aIPv4Subnet['mask'];
							if ($aIPv4SubnetsList[$sIndex]['ipdiscovery_enabled'] == 'yes') {
								$aIPv4SubnetsList[$sIndex]['ipconfig_id'] = $aIPv4Subnet['ipconfig_id'];
								$aIPv4SubnetsList[$sIndex]['gatewayip'] = $aIPv4Subnet['gatewayip'];
								$aIPv4SubnetsList[$sIndex]['broadcastip'] = $aIPv4Subnet['broadcastip'];
								if (array_key_exists('Make usage of dhcp_range_discovery_enabled', $aIPv4Subnet)) {
									$aIPv4SubnetsList[$sIndex]['dhcp_range_discovery_enabled'] = $aIPv4Subnet['dhcp_range_discovery_enabled'];
								} else {
									$aIPv4SubnetsList[$sIndex]['dhcp_range_discovery_enabled'] = 'yes';
								}
								$aIPv4SubnetsList[$sIndex]['ping_enabled'] = $aIPv4Subnet['ping_enabled'];
								$aIPv4SubnetsList[$sIndex]['ping_duration'] = 0;
								$aIPv4SubnetsList[$sIndex]['ping_discovered'] = 0;
								$aIPv4SubnetsList[$sIndex]['iplookup_enabled'] = $aIPv4Subnet['iplookup_enabled'];
								$aIPv4SubnetsList[$sIndex]['iplookup_duration'] = 0;
								$aIPv4SubnetsList[$sIndex]['iplookup_discovered'] = 0;
								$aIPv4SubnetsList[$sIndex]['scan_enabled'] = $aIPv4Subnet['scan_enabled'];
								$aIPv4SubnetsList[$sIndex]['scan_duration'] = 0;
								$aIPv4SubnetsList[$sIndex]['scan_discovered'] = 0;
								$aIPv4SubnetsList[$sIndex]['scan_cnx_refused_enabled'] = $aIPv4Subnet['scan_cnx_refused_enabled'];
								$aIPv4SubnetsList[$sIndex]['last_discovery_date'] = '';

								// Get list of DHCP ranges if needed
								$aIPv4SubnetsList[$sIndex]['dhcp_ranges'] = [];
								if ($aIPv4SubnetsList[$sIndex]['dhcp_range_discovery_enabled'] != 'yes') {
									$aIPv4SubnetsList[$sIndex]['dhcp_ranges'] = $this->GetDHCPRangesInSubnet($aIPv4Subnet['ip'], $aIPv4Subnet['org_id']);
								}
							}
						}

						// Report parameters
						Utils::Log(LOG_INFO, "---------- IP Discovery Parameters ----------");
						Utils::Log(LOG_INFO, "DHCP ranges discovery enabled: ".$aIPDiscoveryAttributes['dhcp_range_discovery_enabled']);
						Utils::Log(LOG_INFO, "Ping enabled: ".$aIPDiscoveryAttributes['ping_enabled']);
						Utils::Log(LOG_INFO, "Ping timeout: ".$aIPDiscoveryAttributes['ping_timeout']);
						Utils::Log(LOG_INFO, "NsLookup enabled: ".$aIPDiscoveryAttributes['iplookup_enabled']);
						Utils::Log(LOG_INFO, "DNS #1: ".$aIPDiscoveryAttributes['dns1']);
						Utils::Log(LOG_INFO, "DNS #2: ".$aIPDiscoveryAttributes['dns2']);
						Utils::Log(LOG_INFO, "Scan enabled: ".$aIPDiscoveryAttributes['scan_enabled']);
						Utils::Log(LOG_INFO, "Port number: ".$aIPDiscoveryAttributes['port_number']);
						Utils::Log(LOG_INFO, "Protocol: ".$aIPDiscoveryAttributes['protocol']);
						Utils::Log(LOG_INFO, "Scan timeout: ".$aIPDiscoveryAttributes['scan_timeout']);
						Utils::Log(LOG_INFO, "Scan \"connection refused\" enabled: ".$aIPDiscoveryAttributes['scan_cnx_refused_enabled']);
						Utils::Log(LOG_INFO, "---------- List of subnets to discover ----------");
						foreach ($aIPv4SubnetsList as $sIp => $aIPv4Subnet) {
							Utils::Log(LOG_INFO, "Subnet: ".$sIp." / ".$aIPv4Subnet['mask']);
							if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
								Utils::Log(LOG_DEBUG, "  Discovery enabled");
								Utils::Log(LOG_DEBUG, "     DHCP ranges discovery enabled: ".$aIPv4Subnet['dhcp_range_discovery_enabled']);
								if ($aIPv4Subnet['dhcp_range_discovery_enabled'] == 'no') {
									Utils::Log(LOG_INFO, "     List of DHCP ranges");
									foreach ($aIPv4Subnet['dhcp_ranges'] as $sRange => $aIPs) {
										Utils::Log(LOG_DEBUG, "          ".$sRange.": ".$aIPs['firstip']." - ".$aIPs['lastip']);
									}
								}
								Utils::Log(LOG_DEBUG, "     Ping enabled: ".$aIPv4Subnet['ping_enabled']);
								Utils::Log(LOG_DEBUG, "     Iplookup enabled: ".$aIPv4Subnet['iplookup_enabled']);
								Utils::Log(LOG_DEBUG, "     Scan enabled: ".$aIPv4Subnet['scan_enabled']);
								Utils::Log(LOG_DEBUG, "     Scan \"connection refused\" enabled: ".$aIPv4Subnet['scan_cnx_refused_enabled']);
							} else {
								Utils::Log(LOG_DEBUG, "  Discovery disabled");
							}
						}
						Utils::Log(LOG_INFO, "---------------------------------------------");
						$bResult = true;
						break;

					default:
						// Ambiguous !!
						Utils::Log(LOG_ERR, "There are ".count($aResult['objects'])." IP Discovery Applications with UUID ".$sApplicationUUID." in iTop.");
						$bResult = false;
				}
			}
		} catch (Exception $e) {
			Utils::Log(LOG_ERR, $e->getMessage());
			$bResult = false;
		}

		return array($bResult, $aIPDiscoveryAttributes, $aIPv4SubnetsList);
	}

	/**
	 * Retrieve from TeemIp the DHCP ranges in a given subnet
	 *
	 * @param $iSubnetIp
	 * @param $iOrgId
	 *
	 * @return array
	 * @throws \Exception
	 */
	protected function GetDHCPRangesInSubnet($iSubnetIp, $iOrgId): array
	{
		$aDHCPRanges = [];
		try {
			$sOQL = "SELECT IPv4Range WHERE subnet_ip = '".$iSubnetIp."' AND org_id = ".$iOrgId." AND dhcp = 'dhcp_yes'";
			$oRestClient = new RestClient();
			$aResult = $oRestClient->Get('IPv4Range', $sOQL, 'range, firstip, lastip');
			if ($aResult['code'] != 0) {
				Utils::Log(LOG_ERR, "{$aResult['message']} ({$aResult['code']})");
			} else {
				if (!is_null($aResult['objects'])) {
					foreach ($aResult['objects'] as $sKey => $aData) {
						$aAttributes = $aData['fields'];
						$aDHCPRanges[$aAttributes['range']] = [
							'firstip' => $aAttributes['firstip'],
							'lastip' => $aAttributes['lastip'],
						];
					}
				}
			}
		} catch (Exception $e) {
			Utils::Log(LOG_ERR, $e->getMessage());
		}

		return $aDHCPRanges;
	}

	/**
	 * Check if TeemIp is installed
	 *
	 * @return bool
	 */
	public function IsTeemIpInstalled(): bool
	{
		return $this->bTeemIpIsInstalled;
	}

	/**
	 * Check if TeemIp Ip Discovey extension is installed
	 *
	 * @return bool
	 */
	public function IsTeemIpIpDiscoveryinstalled(): bool
	{
		return $this->bTeemIpIpDiscoveryIsInstalled;
	}

	/**
	 * Check if TeemIp Network Management Extended extension is installed
	 *
	 * @return bool
	 */
	public function IsTeemIpNMEInstalled(): bool
	{
		return $this->bTeemIpNMEIsInstalled;
	}

	/**
	 * Check if TeemIp Zone Management is installed
	 *
	 * @return bool
	 */
	public function IsTeemIpZoneMgmtInstalled(): bool
	{
		return $this->bTeemIpZoneMgmtIsInstalled;
	}

	/**
	 * Check if TeemIp IP Request Management is installed
	 *
	 * @return bool
	 */
	public function IsTeemIpIPRequestMgmtInstalled(): bool
	{
		return $this->bTeemIpIPRequestMgmtIsInstalled;
	}

	/**
	 * Set an application parameter
	 *
	 * @return bool
	 */
	public function SetApplicationParam($sParam, $sValue): void
	{
		switch ($sParam) {
			case 'UUID':
				$this->aDiscoveryApplication['UUID'] = $sValue;

			case 'last_discovery_date':
				$this->aDiscoveryApplication['last_discovery_date'] = $sValue;

			case 'duration':
				$this->aDiscoveryApplication['duration'] = $sValue;

			default:
		}
	}

	/**
	 * Get an application parameter
	 *
	 * @param $sParam
	 * @return array|string
	 */
	public function GetApplicationParam($sParam)
	{
		switch ($sParam) {
			case 'id':
				return $this->aDiscoveryApplication['params']['id'];
				
			case 'uuid':
				return $this->aDiscoveryApplication['UUID'];

			case 'last_discovery_date':
				if (array_key_exists('last_discovery_date', $this->aDiscoveryApplication)) {
					return $this->aDiscoveryApplication['last_discovery_date'];
				} else {
					return null;
				}

			case 'duration':
				if (array_key_exists('duration', $this->aDiscoveryApplication)) {
					return $this->aDiscoveryApplication['duration'];
				} else {
					return 0;
				}

			case 'params':
				return $this->aDiscoveryApplication['params'];

			default:
				return '';
		}
	}

	/**
	 * Get the list of subnets to be discovered
	 * @param $sIPClass
	 * @return array
	 */
	public function GetSubnetsList($sIPClass): array
	{
		if ($sIPClass == 'ipv4') {
			return $this->aIPv4SubnetsList;
		}

		return [];
	}

	public function SetSubnetParam($sSubnetIp, $sParam, $sValue): void
	{
		if (array_key_exists($sSubnetIp, $this->aIPv4SubnetsList)) {
			$this->aIPv4SubnetsList[$sSubnetIp][$sParam] = $sValue;
		}
	}
}