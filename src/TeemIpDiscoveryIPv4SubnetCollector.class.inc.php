<?php
/*
 * @copyright   Copyright (C) 2023 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPv4SubnetCollector extends Collector
{
	protected $iIndex;
	protected $oCollectionPlan;
	protected $aIPv4Subnet;

	/**
	 * @throws \Exception
	 */
	public function __construct()
	{
		parent::__construct();

		$this->iIndex = 0;
		$this->aIPv4Subnet = array();
	}

	/**
	 * @inheritdoc
	 */
	public function Init(): void
	{
		parent::Init();

		$this->iIndex = 0;

		// Get a copy of the collection plan
		$this->oCollectionPlan = TeemIpDiscoveryCollectionPlan::GetPlan();
	}

	/**
	 * @inheritdoc
	 */
	public function CheckToLaunch($aOrchestratedCollectors): bool
	{
		if (parent::CheckToLaunch($aOrchestratedCollectors)) {
			if ($this->oCollectionPlan->IsTeemIpInstalled() && ($this->oCollectionPlan->GetApplicationParam('uuid') != '')) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return void
	 */
	private function GetSubnets()
	{
		// Read updated subnet list from discovery activity that just took place
		//$aIPv4SubnetsList = TeemIpDiscoveryIPv4Collector::GetUpdatedSubnetList();
		$aIPv4SubnetsList = $this->oCollectionPlan->GetSubnetsList('ipv4');

		$index = 0;
		foreach ($aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
				$this->aIPv4Subnet[$index]['ip'] = $sSubnetIp;
				$this->aIPv4Subnet[$index]['org_id'] = $aIPv4Subnet['org_id'];
				$this->aIPv4Subnet[$index]['ipconfig_id'] = $aIPv4Subnet['ipconfig_id'];
				$this->aIPv4Subnet[$index]['last_discovery_date'] = $aIPv4Subnet['last_discovery_date'];
				$this->aIPv4Subnet[$index]['ping_duration'] = $aIPv4Subnet['ping_duration'];
				$this->aIPv4Subnet[$index]['ping_discovered'] = $aIPv4Subnet['ping_discovered'];
				$this->aIPv4Subnet[$index]['iplookup_duration'] = $aIPv4Subnet['iplookup_duration'];
				$this->aIPv4Subnet[$index]['iplookup_discovered'] = $aIPv4Subnet['iplookup_discovered'];
				$this->aIPv4Subnet[$index]['scan_duration'] = $aIPv4Subnet['scan_duration'];
				$this->aIPv4Subnet[$index]['scan_discovered'] = $aIPv4Subnet['scan_discovered'];
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
		if ($this->iIndex < count($this->aIPv4Subnet)) {
			$aDatas = array();
			$aDatas['primary_key'] = $this->aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['ip'] = $this->aIPv4Subnet[$this->iIndex]['ip'];
			$aDatas['org_id'] = $this->aIPv4Subnet[$this->iIndex]['org_id'];
			$aDatas['ipconfig_id'] = $this->aIPv4Subnet[$this->iIndex]['ipconfig_id'];
			$aDatas['last_discovery_date'] = $this->aIPv4Subnet[$this->iIndex]['last_discovery_date'];
			$aDatas['ping_duration'] = $this->aIPv4Subnet[$this->iIndex]['ping_duration'];
			$aDatas['ping_discovered'] = $this->aIPv4Subnet[$this->iIndex]['ping_discovered'];
			$aDatas['iplookup_duration'] = $this->aIPv4Subnet[$this->iIndex]['iplookup_duration'];
			$aDatas['iplookup_discovered'] = $this->aIPv4Subnet[$this->iIndex]['iplookup_discovered'];
			$aDatas['scan_duration'] = $this->aIPv4Subnet[$this->iIndex]['scan_duration'];
			$aDatas['scan_discovered'] = $this->aIPv4Subnet[$this->iIndex]['scan_discovered'];
			$this->iIndex++;

			return $aDatas;
		}

		return false;
	}

}
