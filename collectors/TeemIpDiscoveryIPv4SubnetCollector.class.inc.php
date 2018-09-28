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

class TeemIpDiscoveryIPv4SubnetCollector extends Collector
{
	protected $iIndex;
	static protected $aIPv4Subnet;

	public function __construct()
	{
		parent::__construct();
		
		$this->iIndex = 0;
		self::$aIPv4Subnet = array();
	}

	public static function GetSubnets()
	{
		// Read updated subnet list from discovery activity that just took place
		$aIPv4SubnetsList = TeemIpDiscoveryIPv4Collector::GetUpdatedSubnetList();

		self::$aIPv4Subnet = array();
		$index = 0;
		foreach ($aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet)
		{
			self::$aIPv4Subnet[$index]['ip'] = $sSubnetIp;
			self::$aIPv4Subnet[$index]['org_id'] = $aIPv4Subnet['org_id'];
			self::$aIPv4Subnet[$index]['last_discovery_date'] = $aIPv4Subnet['last_discovery_date'];
			self::$aIPv4Subnet[$index]['ping_duration'] = $aIPv4Subnet['ping_duration'];
			self::$aIPv4Subnet[$index]['iplookup_duration'] = $aIPv4Subnet['iplookup_duration'];
			self::$aIPv4Subnet[$index]['scan_duration'] = $aIPv4Subnet['scan_duration'];
			$index++;
		}

	}

	public function Prepare()
	{
		$bRet = parent::Prepare();
		if (!$bRet) return false;

		$this->GetSubnets();

		$this->iIndex = 0;
		return true;
	}

	public function fetch()
	{
		if ($this->iIndex < count(self::$aIPv4Subnet))
		{
			$aDatas = array();
			$aDatas['primary_key'] = self::$aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['ip'] = self::$aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['org_id'] = self::$aIPv4Subnet[$this->iIndex]['org_id'];
			$aDatas['last_discovery_date'] = self::$aIPv4Subnet[$this->iIndex]['last_discovery_date'];
			$aDatas['ping_duration'] = self::$aIPv4Subnet[$this->iIndex]['ping_duration'];
			$aDatas['iplookup_duration'] = self::$aIPv4Subnet[$this->iIndex]['iplookup_duration'];
			$aDatas['scan_duration'] = self::$aIPv4Subnet[$this->iIndex]['scan_duration'];
			$this->iIndex++;

			return $aDatas;
		}
		return false;
	}

}
