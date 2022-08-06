<?php
	/**
	* @package		Cuppa CMS
	* @copyright	Copyright (C) 2011 Open Source Matters, T-Golden Group :: tufik2@hotmail.com
	* @Version 		b.0..1 (GPL)
	*/
	
	// Check if the directory installation exist
	if(is_dir('installation')) header ("Location: installation/"); 
	@session_start();
	require("Configuration.php");	
	require("classes/Security.php");
	require("classes/DataBase.php");
	require("classes/User.php");
	require("classes/Menu.php");
	// Configuration File
		$configuration = new Configuration();
		// Validate secure login
			if($configuration->secure_login && @!$_SESSION["admin_login"]){
				if($configuration->secure_login_value != @$_REQUEST["secure"]) header ("Location: " . $configuration->secure_login_redirect);
			}
	// Security Class
		$security = Security::getInstance(); $security->token = $configuration->token; $security->CreateSecurityData();
	// DataBase
		$db = DataBase::getInstance($configuration->db,  $configuration->host, $configuration->user, $configuration->password);
	// User
		$user = User::getInstance();
	//++ Validate user
		if(@$_REQUEST["task"] == "login"){
			$user->CreateUserSession($_REQUEST["user"], $_REQUEST["password"]);
		}else if(@$_REQUEST["task"] == "logout"){
			$user->DestroyUserSession();
		}
	//--
	// Menu Class
		$menu = Menu::getInstance();
		$menu_admin = $menu->GetListMenu("admin_menu", $security->token);
	require("templates/".$configuration->administrator_template."/index.php");
?>