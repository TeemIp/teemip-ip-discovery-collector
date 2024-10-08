<?php
/*
 * @copyright   Copyright (C) 2010-2024 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

SetupWebPage::AddModule(
	__FILE__, // Path to the current file, all other file names are relative to the directory containing this file
	'teemip-ip-discovery-collector/3.2.0',
	array(
		// Identification
		//
		'label' => 'IP Discovery Collector',
		'category' => 'collector',

		// Setup
		//
		'dependencies' => array(),
		'mandatory' => false,
		'visible' => true,

		// Components
		//
		'datamodel' => array(),
		'webservice' => array(),
		'data.struct' => array(// add your 'structure' definition XML files here,
		),
		'data.sample' => array(// add your sample data XML files here,
		),

		// Documentation
		//
		'doc.manual_setup' => '', // hyperlink to manual setup documentation, if any
		'doc.more_information' => '', // hyperlink to more information, if any 

		// Default settings
		//
		'settings' => array(// Module specific settings go here, if any
		),
	)
);
