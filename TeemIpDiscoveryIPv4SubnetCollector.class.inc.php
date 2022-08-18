<?php
/*
 * @copyright   Copyright (C) 2022 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPv4SubnetCollector extends Collector
{
	protected $iIndex;
	static protected $aIPv4Subnet;

	/**
	 * @throws \Exception
	 */
	public function __construct()
	{
		parent::__construct();

		$this->iIndex = 0;
		self::$aIPv4Subnet = array();
	}

	/**
	 * @return void
	 */
	public static function GetSubnets()
	{
		// Read updated subnet list from discovery activity that just took place
		$aIPv4SubnetsList = TeemIpDiscoveryIPv4Collector::GetUpdatedSubnetList();

		$index = 0;
		foreach ($aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
				self::$aIPv4Subnet[$index]['ip'] = $sSubnetIp;
				self::$aIPv4Subnet[$index]['org_id'] = $aIPv4Subnet['org_id'];
				self::$aIPv4Subnet[$index]['last_discovery_date'] = $aIPv4Subnet['last_discovery_date'];
				self::$aIPv4Subnet[$index]['ping_duration'] = $aIPv4Subnet['ping_duration'];
				self::$aIPv4Subnet[$index]['ping_discovered'] = $aIPv4Subnet['ping_discovered'];
				self::$aIPv4Subnet[$index]['iplookup_duration'] = $aIPv4Subnet['iplookup_duration'];
				self::$aIPv4Subnet[$index]['iplookup_discovered'] = $aIPv4Subnet['iplookup_discovered'];
				self::$aIPv4Subnet[$index]['scan_duration'] = $aIPv4Subnet['scan_duration'];
				self::$aIPv4Subnet[$index]['scan_discovered'] = $aIPv4Subnet['scan_discovered'];
				$index++;
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

		$this->GetSubnets();

		$this->iIndex = 0;

		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function fetch()
	{
		if ($this->iIndex < count(self::$aIPv4Subnet)) {
			$aDatas = array();
			$aDatas['primary_key'] = self::$aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['ip'] = self::$aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['org_id'] = self::$aIPv4Subnet[$this->iIndex]['org_id'];
			$aDatas['last_discovery_date'] = self::$aIPv4Subnet[$this->iIndex]['last_discovery_date'];
			$aDatas['ping_duration'] = self::$aIPv4Subnet[$this->iIndex]['ping_duration'];
			$aDatas['ping_discovered'] = self::$aIPv4Subnet[$this->iIndex]['ping_discovered'];
			$aDatas['iplookup_duration'] = self::$aIPv4Subnet[$this->iIndex]['iplookup_duration'];
			$aDatas['iplookup_discovered'] = self::$aIPv4Subnet[$this->iIndex]['iplookup_discovered'];
			$aDatas['scan_duration'] = self::$aIPv4Subnet[$this->iIndex]['scan_duration'];
			$aDatas['scan_discovered'] = self::$aIPv4Subnet[$this->iIndex]['scan_discovered'];
			$this->iIndex++;

			return $aDatas;
		}

		return false;
	}

}
