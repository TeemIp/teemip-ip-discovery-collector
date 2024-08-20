<?php
/*
 * @copyright   Copyright (C) 2010-2024 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPv4SubnetCollector extends Collector
{
	protected int $iIndex = 0;
	protected TeemIpDiscoveryCollectionPlan $oCollectionPlan;
	protected array $aIPv4Subnet = [];

	/**
	 * @inheritdoc
	 */
	public function Init(): void
	{
		parent::Init();

		// Get a copy of the collection plan
		$this->oCollectionPlan = TeemIpDiscoveryCollectionPlan::GetPlan();
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
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4SubnetCollector will not be launched as TeemIp is not installed');
			return false;
		}
		// Make sure that a Discovery Application has been identified
		if ($this->oCollectionPlan->GetApplicationParam('uuid') == '') {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4SubnetCollector will not be launched as no IP Discovery Application has been found');
			return false;
		}
		// Make sure IPs are collected first (i.e. already orchestrated)
		if (!array_key_exists('TeemIpDiscoveryIPv4Collector', $aOrchestratedCollectors)) {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPv4SubnetCollector will not be launched as no TeemIpDiscoveryIPv4Collector has been orchestrated yet. Please check launch sequence!');
			return false;
		}

		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function AttributeIsOptional($sAttCode): bool
	{
		if ($sAttCode == 'allow_automatic_ip_creation') return !$this->oCollectionPlan->IsTeemIpIPRequestMgmtInstalled();

		return parent::AttributeIsOptional($sAttCode);
	}

	/**
	 * @return void
	 */
	private function GetSubnets(): void
	{
		// Read updated subnet list from discovery activity that just took place
		//$aIPv4SubnetsList = TeemIpDiscoveryIPv4Collector::GetUpdatedSubnetList();
		$aIPv4SubnetsList = $this->oCollectionPlan->GetSubnetsList('ipv4');

		foreach ($aIPv4SubnetsList as $sSubnetIp => $aIPv4Subnet) {
			if ($aIPv4Subnet['ipdiscovery_enabled'] == 'yes') {
				$this->aIPv4Subnet[] = [
					'primary_key' => $sSubnetIp,
					'ip' => $sSubnetIp,
					'org_id' => $aIPv4Subnet['org_id'],
					'last_discovery_date' => $aIPv4Subnet['last_discovery_date'],
					'ping_duration' => $aIPv4Subnet['ping_duration'],
					'ping_discovered' => $aIPv4Subnet['ping_discovered'],
					'iplookup_duration' => $aIPv4Subnet['iplookup_duration'],
					'iplookup_discovered' => $aIPv4Subnet['iplookup_discovered'],
					'scan_duration' => $aIPv4Subnet['scan_duration'],
					'scan_discovered' => $aIPv4Subnet['scan_discovered'],
				];
			}
		}

	}

	/**
	 * @inheritdoc
	 */
	public function Prepare(): bool
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
	public function fetch(): mixed
	{
		if ($this->iIndex < count($this->aIPv4Subnet)) {
			return $this->aIPv4Subnet[$this->iIndex++];
		}

		return false;
	}

}
