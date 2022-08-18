<?php
/*
 * @copyright   Copyright (C) 2022 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPApplicationCollector extends Collector
{
	protected $iIndex;
	static protected $aIPApplication;

	/**
	 * @throws \Exception
	 */
	public function __construct()
	{
		parent::__construct();

		$this->iIndex = 0;
		self::$aIPApplication = array();
	}

	/**
	 * @return void
	 */
	public static function GetApplication()
	{
		// Read IP Application parameters from discovery activity that just took place
		$aIPApplicationParams = TeemIpDiscoveryIPv4Collector::GetApplication();

		$index = 0;
		self::$aIPApplication[$index]['uuid'] = $aIPApplicationParams['uuid'];
		self::$aIPApplication[$index]['last_discovery_date'] = $aIPApplicationParams['last_discovery_date'];
		self::$aIPApplication[$index]['duration'] = $aIPApplicationParams['duration'];

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

		$this->GetApplication();
		$this->iIndex = 0;

		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function fetch()
	{
		if ($this->iIndex < count(self::$aIPApplication)) {
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
