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

class TeemIpDiscoveryIPApplicationCollector extends Collector
{
	protected $iIndex;
	static protected $aIPApplication;

	public function __construct()
	{
		parent::__construct();

		$this->iIndex = 0;
		self::$aIPApplication = array();
	}

	public static function GetApplication()
	{
		// Read IP Application parameters from discovery activity that just took place
		$aIPApplicationParams = TeemIpDiscoveryIPv4Collector::GetApplication();

		$index = 0;
		self::$aIPApplication[$index]['uuid'] = $aIPApplicationParams['uuid'];
		self::$aIPApplication[$index]['last_discovery_date'] = $aIPApplicationParams['last_discovery_date'];
		self::$aIPApplication[$index]['duration'] = $aIPApplicationParams['duration'];

	}

	public function Prepare()
	{
		$bRet = parent::Prepare();
		if (!$bRet) return false;

		$this->GetApplication();

		$this->iIndex = 0;
		return true;
	}

	public function fetch()
	{
		if ($this->iIndex < count(self::$aIPApplication))
		{
			$aDatas = array();
			$aDatas['primary_key'] = self::$aIPApplication[$this->iIndex]['uuid'];
			$aDatas['uuid'] = self::$aIPApplication[$this->iIndex]['uuid'];
			$aDatas['last_discovery_date'] = self::$aIPApplication[$this->iIndex]['last_discovery_date'];
			$aDatas['duration'] = self::$aIPApplication[$this->iIndex]['duration'];
			$this->iIndex++;

			return $aDatas;
		}
		return false;
	}

}
