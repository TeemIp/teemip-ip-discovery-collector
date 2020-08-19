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


require_once(APPROOT.'collectors/TeemIpDiscoveryIPv4Collector.class.inc.php');
require_once(APPROOT.'collectors/TeemIpDiscoveryIPv4SubnetCollector.class.inc.php');
require_once(APPROOT.'collectors/TeemIpDiscoveryIPApplicationCollector.class.inc.php');

$index = 1;
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPv4Collector');
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPv4SubnetCollector');
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPApplicationCollector');

