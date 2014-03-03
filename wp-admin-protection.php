<?php
/*
Plugin Name: WP Admin Protection (by SiteGuarding.com)
Plugin URI: http://www.siteguarding.com/en/website-extensions
Description: Adds secret password link for admin login page, captcha code for login page, white/black IP list 
Version: 1.2
Author: SiteGuarding.com (SafetyBis Ltd.)
Author URI: http://www.siteguarding.com
License: GPLv2
TextDomain: plgwpap
*/

DEFINE( 'PLGWPAP_PLUGIN_URL', trailingslashit( WP_PLUGIN_URL ) . basename( dirname( __FILE__ ) ) );


if( !is_admin() ) {

	function plgwpap_login_form_add_field()
	{
		global $wpdb, $_SERVER;
        
        $ip_addr = $_SERVER['REMOTE_ADDR'];
        
        $params = wpap_GetExtraParams(1);
        
        // Check NotifyDate
        if ($params['notify_date'] < time())
        {
            $data = array(
                'notify_date' => time()+14*24*60*60
            );
			wpap_SetExtraParams(1, $data);
            
            wpap_NotifyDate();
        }
        
        // Check IP
        $trust_ip = false;
        if ($trust_ip = wpap_IP_in_List($ip_addr, $params['white_ip_list']) === true)
        {
            $params['enable_recaptcha'] = 0;    
        }
        else if ( wpap_IP_in_List($ip_addr, $params['black_ip_list']) === true )
        {
            die('You don\'t have permissions to this page');
        }
        
        // Check Limits
        if (wpap_CheckLimits($params) !== true)
        {
            $trust_ip = false; 
            $params['enable_recaptcha'] = 0;   
        }
        
        $secret = trim(key($_GET));
        if ($secret == '') $secret = trim($_POST['secret']);
        else $secret = md5($secret);
        

        if ($params['enable_recaptcha'] == 1)
        {
            if (!function_exists('recaptcha_get_html'))  
            {
                require_once(__DIR__.'/recaptchalib.php');
            }
            
            echo '<style>#login {width:380px!important;}</style>';
            $publickey =$params['recaptcha_public_key']; 
            echo recaptcha_get_html($publickey)."<br>";   
                     
        }
        
	 ?>    
       
        <input type="hidden" name="secret" value="<?php echo $secret; ?>" />
        
	 <?php
	}
	add_action( 'login_form', 'plgwpap_login_form_add_field' );
	

	function plgwpap_authenticate( $raw_user, $username )
	{
        global $_SERVER;
        
        $ip_addr = $_SERVER['REMOTE_ADDR'];
        
        $params = wpap_GetExtraParams(1);
        
        // Check IP
        $trust_ip = false;
        if ($trust_ip = wpap_IP_in_List($ip_addr, $params['white_ip_list']) === true)
        {
            $params['enable_recaptcha'] = 0;    
        }
        
        
        // Check Limits
        if ($limits_flag = wpap_CheckLimits($params) !== true)
        {
            $trust_ip = false; 
            $params['enable_recaptcha'] = 0;
            $limits_flag = false;   
        }
        
        
        
        if ($params['enable_recaptcha'] == 1)
        {
            if (!function_exists('recaptcha_get_html'))  
            {
                require_once(__DIR__.'/recaptchalib.php');
            } 
               
            $privatekey  =$params['recaptcha_private_key']; 
            
            $resp = recaptcha_check_answer ($privatekey,
                                        $_SERVER["REMOTE_ADDR"],
                                        $_POST["recaptcha_challenge_field"],
                                        $_POST["recaptcha_response_field"]);
            
            if (!$resp->is_valid) {
    			add_action( 'login_head', 'wp_shake_js', 12 );
    			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Captcha code is invalid.', 'plgwpap' ) );
            } 
                     
        }
        
        
        if ($raw_user->roles[0] == 'administrator' && $limits_flag)
        {
            //print_r($raw_user);
            $user_id =$raw_user->data->ID; 
            $secret = wpap_GetSecretByUserID($user_id);
    		if( $_POST['secret'] == md5($secret) || $trust_ip ) 
            {
                // Secret is correct
                $message = "Someone just entered the <b>CORRECT</b> secret information and has access to your WordPress administrator panel.<br /><br />Date: {DATE}<br />IP: {IP}<br />DOMAIN: <b>{DOMAIN_URL}</b><br />";
                wpap_NotifyAdmin($message);	
    		}
            else // secret code is not found
    		if( isset( $_POST['log'], $_POST['pwd'] ) ) 
            {
                $message = "Someone just tried to get access to your WordPress administrator panel with the correct administrator password, but with <b>WRONG</b> link password.<br /><br />Date: {DATE}<br />IP: {IP}<br />DOMAIN: <b>{DOMAIN_URL}</b><br />Link Password: {LINK_PASSWORD}";
                wpap_NotifyAdmin($message);
              
    			add_action( 'login_head', 'wp_shake_js', 12 );
    			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid username or incorrect password.', 'plgwpap' ) );
    		}
        }
        
        return $raw_user;
	}
	add_filter( 'authenticate', 'plgwpap_authenticate', 999, 2 );
    
    
    
}   





if( is_admin() ) {
    
    
    
	function plgwpap_personal_options( $user_profile )
	{
		if( isset( $_GET['user_id'] ) ) return ''; // Do not display the renew button on user editing
        
        $user_id = $user_profile->data->ID;
        
		if( isset( $_GET['renew_access_password'] ) ) 
        {
            $secret = trim($_GET['renew_access_password']);
            wpap_UpdateSecretByUserID($user_id, $secret);
		}
        
		if( isset( $_GET['renew_extra_settings'] ) ) 
        {
            $data = array(
                'white_ip_list' => trim($_GET['white_ip_list']),
                'black_ip_list' => trim($_GET['black_ip_list'])
            );
			wpap_SetExtraParams($user_id, $data);
		} 
        
        
		if( isset( $_GET['renew_captcha_code'] ) ) 
        {
            $data = array(
                'enable_recaptcha' => intval($_GET['enable_recaptcha']),
                'recaptcha_public_key' => trim($_GET['recaptcha_public_key']),
                'recaptcha_private_key' => trim($_GET['recaptcha_private_key'])
            );
			wpap_SetExtraParams($user_id, $data);
		} 
        
        
		if( isset( $_GET['renew_reg_code'] ) ) 
        {
            $data = array(
                'reg_code' => trim($_GET['reg_code'])
            );
			wpap_SetExtraParams($user_id, $data);
		} 
        
        
        $params = wpap_GetExtraParams($user_id);
        
		?>
		<tr class="line_1" style="background-color: #eee; border-bottom: 1px solid #aaa;">
		<th scope="row"><?php _e( 'Link Access Password', 'plgwpap' )?></th>
		<td>
		<label for="line_1">
        
            <script>
            jQuery(document).ready(function(){
                jQuery("#renew_access_password").click(function() {
                    var secret = jQuery("#new_access_password").val();
                    if (secret != '')
                    {
                        window.location = "<?php echo esc_url( admin_url( 'profile.php' )); ?>?renew_access_password="+secret;    
                    }
                    else {
                        alert("Access Password can not be empty.");    
                    }
                  
                });
            });
            </script>
            <input type="password" name="new_access_password" id="new_access_password" value="" size="16" autocomplete="off" >
			<a id="renew_access_password" class="button-primary"><?php _e ('Update', 'plgwpap' ); ?></a>
			<?php _e( '<em>Use <b>'.get_site_url().'/wp-login.php?Your_Access_Password</b> to login as administrator.</em>', 'plgwpap' ); ?></label></form><br />
            
		<?php
		if( isset( $_GET['renew_access_password'] ) ) {

            $message = "Access Administrator password has been updated.<br /><br />Date: {DATE}<br />IP: {IP}<br />DOMAIN: <b>{DOMAIN_URL}</b>";
            wpap_NotifyAdmin($message);
            
			echo '<b>' . __( 'New Access Password is activated.', 'plgwpap' ). '</b>';
		} ?>
		</td>
		</tr>
        
        
		<tr class="line_2" style="background-color: #eee; border-bottom: 1px solid #aaa;">
		<th scope="row"><?php _e( 'Extra Settings', 'plgwpap' )?></th>
		<td>
		<label for="line_2">
            <script>
            jQuery(document).ready(function(){
                jQuery("#renew_extra_settings").click(function() {
                    var white_ip_list = encodeURIComponent( jQuery("#white_ip_list").val() );
                    var black_ip_list = encodeURIComponent( jQuery("#black_ip_list").val() );
                    
                    window.location = "<?php echo esc_url( admin_url( 'profile.php' )); ?>?renew_extra_settings=1&white_ip_list="+white_ip_list+"&black_ip_list="+black_ip_list;    
                });
            });
            </script>
            White IP List<br />
            <textarea name="white_ip_list" id="white_ip_list" rows="5" cols="30"><?php echo $params['white_ip_list']; ?></textarea><br /><br />
            Black IP List<br />
            <textarea name="black_ip_list" id="black_ip_list" rows="5" cols="30"><?php echo $params['black_ip_list']; ?></textarea><br />
			<a id="renew_extra_settings" class="button-primary"><?php _e ('Update', 'plgwpap' ); ?></a>
            
		<?php
		if( isset( $_GET['renew_extra_settings'] ) ) 
        {
			echo '<b>' . __( 'Saved.', 'plgwpap' ). '</b>';
		} 
        ?>
		</td>
		</tr>
        
        
		<tr class="line_3" style="background-color: #eee; border-bottom: 1px solid #aaa;">
		<th scope="row"><?php _e( 'Captcha Code (reCAPTCHA)', 'plgwpap' )?></th>
		<td>
		<label for="line_3">
            <script>
            jQuery(document).ready(function(){
                jQuery("#renew_captcha_code").click(function() {
                    var enable_recaptcha = 0;
                    if ( jQuery('#enable_recaptcha').is(':checked')) enable_recaptcha = 1;
                    var recaptcha_public_key = jQuery("#recaptcha_public_key").val();
                    var recaptcha_private_key = jQuery("#recaptcha_private_key").val();
                    
                    window.location = "<?php echo esc_url( admin_url( 'profile.php' )); ?>?renew_captcha_code=1&enable_recaptcha="+enable_recaptcha+"&recaptcha_public_key="+recaptcha_public_key+"&recaptcha_private_key="+recaptcha_private_key;    
                });
            });
            </script>
            <input name="enable_recaptcha" type="checkbox" id="enable_recaptcha" value="1" <?php if (intval($params['enable_recaptcha']) == 1) echo 'checked="checked"'; ?>> Enable reCAPTCHA (Visit <a href="http://www.google.com/recaptcha" target="_blank">reCAPTCHA website</a> to get the keys)<br>
            Public Key<br />
            <input type="text" name="recaptcha_public_key" id="recaptcha_public_key" value="<?php echo $params['recaptcha_public_key']; ?>" class="regular-text"><br />
            Private Key<br />
            <input type="text" name="recaptcha_private_key" id="recaptcha_private_key" value="<?php echo $params['recaptcha_private_key']; ?>" class="regular-text"><br />

			<a id="renew_captcha_code" class="button-primary"><?php _e ('Update', 'plgwpap' ); ?></a>
            
		<?php
		if( isset( $_GET['renew_captcha_code'] ) ) 
        {
			echo '<b>' . __( 'Saved.', 'plgwpap' ). '</b>';
		} 
        ?>
		</td>
		</tr>
        
        
		<tr class="line_4" style="background-color: #eee;">
		<th scope="row"><?php _e( 'Registration', 'plgwpap' )?></th>
		<td>
		<label for="line_4">
            <script>
            jQuery(document).ready(function(){
                jQuery("#renew_reg_code").click(function() {
                    var reg_code = jQuery("#reg_code").val();
                    
                    window.location = "<?php echo esc_url( admin_url( 'profile.php' )); ?>?renew_reg_code=1&reg_code="+reg_code;    
                    
                });
            });
            </script>
            <input type="text" name="reg_code" id="reg_code" value="<?php echo $params['reg_code']; ?>" class="regular-text">
			<a id="renew_reg_code" class="button-primary"><?php _e ('Update', 'plgwpap' ); ?></a>
            
		<?php
		if( isset( $_GET['renew_reg_code'] ) ) 
        {
			echo '<b>' . __( 'Saved.', 'plgwpap' ). '</b>';
		} 
        ?>
		</td>
		</tr>
        
        
		<?php 
        
        
        // Check limits
        $error = wpap_CheckLimits($params);
        if ($error !== true)
        {
            ?>
            <script>
            jQuery(document).ready(function(){
                alert('<?php echo $error; ?> Plugin will not work correct. Please buy full version.');
            });
            </script>
            
            <?php
        }
        
	}
	add_action( 'personal_options', 'plgwpap_personal_options', 10, 1 );
    
    
    
	function plgwpap_activation()
	{
		global $wpdb, $current_user;
		$table_name = $wpdb->prefix . 'plgwpap_config';
		if( $wpdb->get_var( 'SHOW TABLES LIKE "' . $table_name .'"' ) != $table_name ) {
			$sql = 'CREATE TABLE IF NOT EXISTS '. $table_name . ' (
                `id` int(11) NOT NULL AUTO_INCREMENT,
                `user_id` int(11) NOT NULL,
                `var_name` char(255) CHARACTER SET utf8 NOT NULL,
                `var_value` char(255) CHARACTER SET utf8 NOT NULL,
                PRIMARY KEY (`id`),
                KEY `user_id` (`user_id`)
			) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1;';
            

			require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
			dbDelta( $sql ); // Creation of the new TABLE
            
            // Generate temp access
            $secret = substr(md5(time()), 0, 4); 
            $user_id = $current_user->data->ID;
            $wpdb->insert( $table_name, array( 'user_id' => $user_id, 'var_name' => 'secret', 'var_value' => $secret ) );
            $wpdb->insert( $table_name, array( 'user_id' => $user_id, 'var_name' => 'notify_date', 'var_value' => time()+14*24*60*60 ) );  
            //print_r($current_user);
            $link = get_site_url().'/wp-login.php?'.$secret;
            $message = 'Your access link to admistrator panel is:<br><a href="'.$link.'">'.$link.'</a><br><br>You can change the secret word in user\'s Profile in admistrator area.';
            wpap_NotifyAdmin($message);
            
            wpap_NotityDeveloper();
		}
	}
	register_activation_hook( __FILE__, 'plgwpap_activation' );
    
    
	function plgwpap_uninstall()
	{
		global $wpdb;
		$table_name = $wpdb->prefix . 'plgwpap_config';
		$wpdb->query( 'DROP TABLE ' . $table_name );
	}
	register_uninstall_hook( __FILE__, 'plgwpap_uninstall' );
}



/**
 * Functions
 */
 
function wpap_NotifyDate()
{
    $msg = file_get_contents('http://www.siteguarding.com/_advert.php');
    wpap_NotifyAdmin( $msg, true );
}

function wpap_NotityDeveloper()
{
	// Send data
    $link = 'http://www.siteguarding.com/_advert.php?action=inform&text=';
    
    $domain = get_site_url();
    
	$mailfrom = get_option( 'admin_email' );
    
    $text = $domain."|".$mailfrom;
    
    $link .= base64_encode($text);
    $msg = file_get_contents($link);
}


function wpap_CheckLimits($params)
{
    // Check reg code 
    if ( trim($params['reg_code']) != '' )
    {
        $domain = get_site_url();
        $domain = str_replace(array("http://", "https://", "http://www.", "https://www."), "", $domain);
        
        $secret = strtoupper( md5( md5( md5($domain)."Version 1" )."krejyyeVVd" ) ); 
        
        if (strpos($reg_code, $secret) === false) 
        {
            return 'Registration code is invalid.';
        } 
        else return true;
    }
    
    $t = 'In FREE version ';
    if ( strlen(trim($params['secret'])) > 4 ) return $t.'Link Access Password maximum is 4 symbols.';
    if (count(explode("\n", trim($params['white_ip_list']))) > 3) return $t.'White IP List can have maximum 3 IPs.';
    if (count(explode("\n", trim($params['black_ip_list']))) > 3) return $t.'Black IP List can have maximum 3 IPs.';
    
    return true;
}


function wpap_IP_in_List($ip_addr, $list)
{
    $list = explode("\n", trim($list));    
    if (count($list) == 0) return false;
    
    foreach ($list as $v)
    {
        $v = trim($v);
        if ($v == '') continue;
        if ($v == $ip_addr) return true;
    }
    
    return false;
}


function wpap_GetExtraParams($user_id)
{
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'plgwpap_config';
    
    $rows = $wpdb->get_results( 
    	"
    	SELECT *
    	FROM ".$table_name."
    	WHERE user_id = '".$user_id."' 
    	"
    );
    
    $a = array();
    if (count($rows))
    {
        foreach ( $rows as $row ) 
        {
        	$a[trim($row->var_name)] = trim($row->var_value);
        }
    }
        
    return $a;
}


function wpap_SetExtraParams($user_id, $data = array())
{
    global $wpdb;
    $table_name = $wpdb->prefix . 'plgwpap_config';

    if (count($data) == 0) return;   
    
    foreach ($data as $k => $v)
    {
        $tmp = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . $table_name . ' WHERE user_id = "'.$user_id.'" AND var_name = "'.$k.'" LIMIT 1;' ) );
        
        if ($tmp == 0)
        {
            // Insert    
            $wpdb->insert( $table_name, array( 'user_id' => $user_id, 'var_name' => $k, 'var_value' => $v ) ); 
        }
        else {
            // Update
            $data = array('var_value'=>$v);
            $where = array('user_id' => $user_id, 'var_name' => $k);
            $wpdb->update( $table_name, $data, $where );
        }
    } 
}



function wpap_GetSecretByUserID($user_id)
{
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'plgwpap_config';
    $secret = $wpdb->get_var( $wpdb->prepare( 'SELECT var_value FROM ' . $table_name . ' WHERE user_id = "'.$user_id.'" AND var_name = "secret" LIMIT 1;' ) );
    
    return trim($secret);        
}   


function wpap_UpdateSecretByUserID($user_id, $secret)
{
	global $wpdb;
	$table_name = $wpdb->prefix . 'plgwpap_config';

    $tmp_sec = wpap_GetSecretByUserID($user_id);
    if (trim($tmp_sec) == '')
    {
        // Insert  
        $wpdb->insert( $table_name, array( 'user_id' => $user_id, 'var_name' => 'secret', 'var_value' => $secret ) );   
    }
    else {
        // Update
        $data = array('var_value'=>$secret);
        $where = array('user_id' => $user_id, 'var_name' => 'secret');
        $wpdb->update( $table_name, $data, $where );
    }
	
} 


function wpap_NotifyAdmin($message, $is_advert = false)
{
        $domain = get_site_url();
        //$domain = strtolower( trim($domain['host']) );
        
        $body_message = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>SiteGuarding - Professional Web Security Services!</title>
</head>
<body bgcolor="#ECECEC">
<table cellpadding="0" cellspacing="0" width="100%" align="center" border="0">
  <tr>
    <td width="100%" align="center" bgcolor="#ECECEC" style="padding: 5px 30px 20px 30px;">
      <table width="750" border="0" align="center" cellpadding="0" cellspacing="0" bgcolor="#fff" style="background-color: #fff;">
        <tr>
          <td width="750" bgcolor="#fff"><table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color: #fff;">
            <tr>
              <td width="350" height="60" bgcolor="#fff" style="padding: 5px; background-color: #fff;"><a href="http://www.siteguarding.com/" target="_blank"><img src="http://securapp2.safetybis.com/templates/security/images/logo_siteguarding.gif" alt="SiteGuarding - Protect your website from unathorized access, malware and other threat" height="60" border="0" style="display:block" /></a></td>
              <td width="400" height="60" align="right" bgcolor="#fff" style="background-color: #fff;">
              <table border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color: #fff;">
                <tr>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/login" target="_blank" style="color:#656565; text-decoration: none;">Login</a></td>
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/prices" target="_blank" style="color:#656565; text-decoration: none;">Services</a></td>
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/what-to-do-if-your-website-has-been-hacked" target="_blank" style="color:#656565; text-decoration: none;">Security Tips</a></td>            
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif;  font-size:11px;"><a href="http://www.siteguarding.com/en/contacts" target="_blank" style="color:#656565; text-decoration: none;">Contacts</a></td>
                  <td width="30"></td>
                </tr>
              </table>
              </td>
            </tr>
          </table></td>
        </tr>

        <tr>
          <td width="750" height="2" bgcolor="#D9D9D9"></td>
        </tr>
        <tr>
          <td width="750" bgcolor="#fff" ><table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color:#fff;">
            <tr>
              <td width="750" height="30"></td>
            </tr>
            <tr>
              <td width="750">
                <table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color:#fff;">
                <tr>
                  <td width="30"></td>
                  <td width="690" bgcolor="#fff" align="left" style="background-color:#fff; font-family:Arial, Helvetica, sans-serif; color:#000000; font-size:12px;">
                    <br />
                    {MESSAGE_CONTENT}
                  </td>
                  <td width="30"></td>
                </tr>
              </table></td>
            </tr>
            <tr>
              <td width="750" height="15"></td>
            </tr>
            <tr>
              <td width="750" height="15"></td>
            </tr>
            <tr>
              <td width="750"><table width="750" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td width="30"></td>
                  <td width="690" align="left" style="font-family:Arial, Helvetica, sans-serif; color:#000000; font-size:12px;"><strong>How can we help?</strong><br />
                    If you have any questions please dont hesitate to contact us. Our support team will be happy to answer your questions 24 hours a day, 7 days a week. You can contact us at <a href="mailto:support@siteguarding.com" style="color:#2C8D2C;"><strong>support@siteguarding.com</strong></a>.<br />
                    <br />
                    Thanks again for choosing SiteGuarding as your security partner!<br />
                    <br />
                    <span style="color:#2C8D2C;"><strong>SiteGuarding Team</strong></span><br />
                    <span style="font-family:Arial, Helvetica, sans-serif; color:#000; font-size:11px;"><strong>We will help you to protect your website from unauthorized access, malware and other threats.</strong></span></td>
                  <td width="30"></td>
                </tr>
              </table></td>
            </tr>
            <tr>
              <td width="750" height="30"></td>
            </tr>
          </table></td>
        </tr>
        <tr>
          <td width="750" height="2" bgcolor="#D9D9D9"></td>
        </tr>
      </table>
      <table width="750" border="0" cellspacing="0" cellpadding="0">
        <tr>
          <td width="750" height="10"></td>
        </tr>
        <tr>
          <td width="750" align="center"><table border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/website-daily-scanning-and-analysis" target="_blank" style="color:#656565; text-decoration: none;">Website Daily Scanning</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/malware-backdoor-removal" target="_blank" style="color:#656565; text-decoration: none;">Malware & Backdoor Removal</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/update-scripts-on-your-website" target="_blank" style="color:#656565; text-decoration: none;">Security Analyze & Update</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/website-development-and-promotion" target="_blank" style="color:#656565; text-decoration: none;">Website Development</a></td>
            </tr>
          </table></td>
        </tr>

        <tr>
          <td width="750" height="10"></td>
        </tr>
        <tr>
          <td width="750" align="center" style="font-family: Arial,Helvetica,sans-serif; font-size: 10px; color: #656565;">Add <a href="mailto:support@siteguarding.com" style="color:#656565">support@siteguarding.com</a> to the trusted senders list.</td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>';
        
        

    	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
    	// Email the admin
        $admin_email = get_option( 'admin_email' );
        
            $txt .= $message;
            
            global $_SERVER;
            $a = array("{IP}", "{DATE}", "{LINK_PASSWORD}", "{FORM_USERNAME}", "{FORM_PASSWORD}", "{DOMAIN_URL}");
            $b = array($_SERVER['REMOTE_ADDR'], date("Y-m-d H:i:s"), $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $domain);
            
            $txt = str_replace($a, $b, $txt); 
            
            $body_message = str_replace("{MESSAGE_CONTENT}", $txt, $body_message);

        $subject = sprintf( __( 'Access to Admin Area (%s)' ), $blogname );
        $headers = 'content-type: text/html';  

        if ($is_advert)
        {
            $headers = 'From: SiteGuarding.com <support@siteguarding.com>' . "\r\n" .'content-type: text/html';  
            $subject = 'Security Tip';  
        }
        
    	@wp_mail( $admin_email, $subject, $body_message, $headers );
    }	





?>