<?php
/*
Plugin Name: WP Admin Protection (by SiteGuarding.com)
Plugin URI: http://www.siteguarding.com/en/website-extensions
Description: Adds secret password link for admin login page, captcha code for login page, white/black IP list 
Version: 2.1
Author: SiteGuarding.com (SafetyBis Ltd.)
Author URI: http://www.siteguarding.com
License: GPLv2
TextDomain: plgwpap
*/
define( 'PLGWPAP_SVN', true);

error_reporting(E_ERROR);

if( !is_admin() ) {

	function plgwpap_login_form_add_field()
	{
		global $wpdb;
        
        $ip_addr = $_SERVER['REMOTE_ADDR'];
        
        $params = wpap_GetExtraParams(1);
        
                if ($params['notify_date'] < time())
        {
            $data = array(
                'notify_date' => time()+14*24*60*60
            );
			wpap_SetExtraParams(1, $data);
            
            wpap_NotifyDate();
        }
        
                $trust_ip = false;
        if ($trust_ip = wpap_IP_in_List($ip_addr, $params['white_ip_list']) === true)
        {
            $params['enable_recaptcha'] = 0;    
        }
        else if ( wpap_IP_in_List($ip_addr, $params['black_ip_list']) === true )
        {
            die('You don\'t have permissions to this page');
        }
        
                $limits_flag = wpap_CheckLimits($params);
        if ($limits_flag !== true)
        {
            $trust_ip = false; 
            $params['enable_recaptcha'] = 0; 

			echo '<p style="background-color: #FFEBE8; border: 1px solid #CC0000; padding:5px; margin: 5px 0">'.$limits_flag.' <b>Plugin is disabled.</b> For PRO version please <a target="_blank" href="https://www.siteguarding.com/en/wordpress-admin-protection">click here</a></p>';

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
       
        <input type="hidden" name="secret" value="<?php echo esc_attr($secret); ?>" />
        
	 <?php
	}
	add_action( 'login_form', 'plgwpap_login_form_add_field' );
	

	function plgwpap_login_head_add_field()
	{
		if (!PLGWPAP_SVN)
		{
			$params = wpap_GetExtraParams(1);
			if (isset($params['show_copyright']) && $params['show_copyright'] == 1)
			{
			?>
				<div style="padding:3px 0;position: fixed;bottom:0;z-index:10;width:100%;text-align:center;background-color:#F1F1F1">Protected by <a href="http://www.siteguarding.com" rel="nofollow" target="_blank" title="SiteGuarding.com - Website Security. Professional security services against hacker activity. Daily website file scanning and file changes monitoring. Malware detecting and removal.">SiteGuarding.com</a></div>
			<?php
			}
		}
	}
	add_action( 'login_head', 'plgwpap_login_head_add_field' );
	
	

	function plgwpap_authenticate( $raw_user, $username )
	{
                
        $ip_addr = $_SERVER['REMOTE_ADDR'];
        
        $params = wpap_GetExtraParams(1);
        
                $trust_ip = false;
        if ($trust_ip = wpap_IP_in_List($ip_addr, $params['white_ip_list']) === true)
        {
            $params['enable_recaptcha'] = 0;    
        }
        
        
                $limits_flag = wpap_CheckLimits($params);
        if ( $limits_flag !== true)
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
                        			$secret = trim($params['secret']);
			
				
			if (intval($params['enable_secret']) == 1)
			{
	    		if( $_POST['secret'] == md5($secret) || $trust_ip ) 
	            {
	                	                	                		                $message = "Someone just entered the <b>CORRECT</b> secret information and has access to your WordPress administrator panel.<br /><br />Date: {DATE}<br />IP: {IP}<br />DOMAIN: <b>{DOMAIN_URL}</b><br />";
		                wpap_NotifyAdmin($message);		
	                	    		}
	            else 	    		if( isset( $_POST['log'], $_POST['pwd'] ) ) 
	            {
	                	                		                $message = "Someone just tried to get access to your WordPress administrator panel with the correct administrator password, but with <b>WRONG</b> link password.<br /><br />Date: {DATE}<br />IP: {IP}<br />DOMAIN: <b>{DOMAIN_URL}</b><br />Link Password: {LINK_PASSWORD}";
		                wpap_NotifyAdmin($message);
	                	              
	    			add_action( 'login_head', 'wp_shake_js', 12 );
	    			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid username or incorrect password.', 'plgwpap' ) );
	    		}
    		}
        }

        return $raw_user;
	}
	add_filter( 'authenticate', 'plgwpap_authenticate', 999, 2 );
    
    
    
}   





if( is_admin() ) {
	
	
	
	add_action('admin_menu', 'register_plgwpap_settings_page');

	function register_plgwpap_settings_page() {
		add_submenu_page( 'options-general.php', 'Admin Protection', 'Admin Protection', 'manage_options', 'plgwpap_settings_page', 'plgwpap_settings_page_callback' ); 
	}

	function plgwpap_settings_page_callback() 
	{
		$domain = get_site_url();
		
		if (isset($_POST['action']) && $_POST['action'] == 'update' && check_admin_referer( 'name_4270F1807ED0' ))
		{
			if (isset($_POST['notify_developer'])) $notify_developer = intval($_POST['notify_developer']);
			else $notify_developer = 0;
			
			$notify_developer_sent = intval($_POST['notify_developer_sent']);
			if ($notify_developer && $notify_developer_sent == 0)
			{
				$notify_developer_sent = 1;
				wpap_NotityDeveloper();	
			}
			
			
			$params = array(
				'enable_secret' => intval($_POST['enable_secret']),
				'secret' => trim($_POST['secret']),
				
												
				'white_ip_list' => trim($_POST['white_ip_list']),
				'black_ip_list' => trim($_POST['black_ip_list']),
				'enable_recaptcha' => intval($_POST['enable_recaptcha']),
				'recaptcha_public_key' => trim($_POST['recaptcha_public_key']),
				'recaptcha_private_key' => trim($_POST['recaptcha_private_key']),
				'show_copyright' => intval($_POST['show_copyright']),
				'notify_developer' => $notify_developer,
				'notify_developer_sent' => $notify_developer_sent,
				'reg_code' => trim($_POST['reg_code'])
			);
			
			$error = wpap_CheckLimits($params, true);
			if ($error !== true) $params['show_copyright'] = 1;
			
			wpap_SetExtraParams(1, $params);
			
                        if ($params['enable_secret'] == 1 & $params['secret'] != '') 
            {
	            $link = get_site_url().'/wp-login.php?'.$params['secret'];
	            $message = 'Your access link to WordPress admistrator panel is:<br><a href="'.$link.'">'.$link.'</a><br><br>You can change the secret word in Settings setion.';
	            wpap_NotifyAdmin($message, 'WP Admin Protection - new access link');
            }
            
			echo '<div id="setting-error-settings_updated" class="updated settings-error"><p><strong>Settings saved.</strong></p></div>';

		}
		else $params = wpap_GetExtraParams(1);
		
		        $error = wpap_CheckLimits($params);
        if ($error !== true)
        {
            ?>
            <script>
            jQuery(document).ready(function(){
                alert('<?php echo $error; ?> Plugin will not work correct. Please get PRO version.');
            });
            </script>
            
            <?php
        }
		
		
		echo '<div class="wrap"><div id="icon-tools" class="icon32"></div>';
			
			?>
			
			
<style>
.mod-box {
	border: 1px solid #d2d2d2;
	border: 1px solid rgba(0,0,0,0.1);
	border-bottom-color: #9d9d9d;
	border-bottom-color: rgba(0,0,0,0.25);
	padding-bottom: 4px;
	border-radius: 4px;
	background: #d2d2d2 url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAMCAYAAABbayygAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEgAACxIB0t1+/AAAABZ0RVh0Q3JlYXRpb24gVGltZQAwMS8yMS8xMRTK2QYAAAAedEVYdFNvZnR3YXJlAEFkb2JlIEZpcmV3b3JrcyBDUzUuMasfSOsAAAAkSURBVBiVYzx79ux/BiIAEzGKRhUSBCy/f/+mssJfv34RpRAAXCgMVFSU87YAAAAASUVORK5CYII=') 0 100% repeat-x;
	background-clip: padding-box;
	box-shadow: 0 1px 2px rgba(0,0,0,0.08);
	text-shadow: 0 1px 0 rgba(255,255,255,0.6);
	margin-bottom:20px;
	/*min-width:500px;*/
	max-width:800px;
	position: relative;
}

.mod-box > div {
	padding: 20px;
	border-radius: 3px;
	background: #f7f7f9;
	box-shadow: inset 0 0 0 1px #fff;
}
.imgpos { 
	bottom: 3px;
	position: absolute;
	right: 0px;
}

.imgpos_ext { 
	bottom: 15px;
	position: absolute;
	right: 15px;
	max-width:60px;
}

.module .module-title { 
font-size: 15px;
margin-bottom: 10px;
margin-top:0;
padding-bottom: 18px;
}

.extbttn{text-shadow: none!important;}

.mod-box .module-title {border-bottom:3px solid #f79432}
.table-vat {vertical-align: top;}
.table-vat ul{padding-left: 30px;}

.grid-box{float:left; margin:0 10px 20px 0}
.deepest{min-height: 295px;}
</style>

		<h3>Learn more about our Security Extentions for your website</h3>

		<div class="grid-box width25 grid-h" style="width: 250px;">
		  <div class="module mod-box widget_black_studio_tinymce">
		    <div class="deepest">
		      <h3 class="module-title">WP Antivirus Site Protection</h3>
		      <div class="textwidget">
		        <table class="table-val" style="height: 180px;">
		          <tbody>
		            <tr>
		              <td class="table-vat">
		                <ul style="list-style-type: circle;">
		                  <li>
		                    Deep scan of every file on your website
		                  </li>
		                  <li>
                    		Advanced Heuristic Logic to find more viruses
		                  </li>
		                  <li>
		                    Daily update of the virus database
		                  </li>
		                  <li>
		                    Daily cron for automatical scanning
		                  </li>
		                </ul>
		              </td>
		            </tr>
		            <tr>
		              <td class="table-vab">
		                <a class="button button-primary extbttn" href="https://www.siteguarding.com/en/antivirus-site-protection">
		                  Learn More
		                </a>
		              </td>
		            </tr>
		          </tbody>
		        </table>
		        <p>
		          <img class="imgpos_ext" alt="WordPress Antivirus Site Protection" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADwAAAA8CAIAAAC1nk4lAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAADvFJREFUeNrsWglUVOcV5s0+A8wGzDAwA7Jv4oKIiBpTEcU1mqNJjFrTnprUxGoW26hZ2sSm55iksT2Np2nMqXVJck6SJqeminHfoyC4ISADyDIwwwzD7PvW783TCQGGCJq2yfExjo9//vfe93/33u/e+w+Mce+Mj/ihHbSIH+BxH/R90PdB/x8cjLu/RSAi4PV5vX4vzgmCRkQE/7/1EfmGCThwxqQzGTTG/xi0z+9z+9x0gi4XyHMkObmSnNSYVEm0hMVg0WikDX0+v9Pj1JjVzfrm6911DboGjUWDNbAZbBpB+2+D9gV8Tq9LxBbOTJtZnl1eIB8fGxUbfvo46r8uU1dlW1XFjQOVHVUOj2PE0InhZkTw5PK6oliRczLnPDb+sdz4XGpca9E26ZoatDdU5g6dVefyujHIZXGlUdIkgSIjLiMjLlMcKaImn795fm/Nh6daT2HxLDrr+2XaH/C7ve5C+cRflTxTNKoIIw63/fTNs8eUx2q6atQWNRzGF/BTzhz8FwCXeDFpzERBYpGiaHbmrEnJk4pTiotHFX95/cv3L+xo1Cu5TA4RQXwvTFOh9vi4x58uWSPgCnw+36GGQ7tr9tRqa+HZIIxOo1PPDkL3selsmAUf0SJo+IgKgEhWZJG8aGXhiikpUzBTZVBtPfHmYeXhYbkKPX627E7mefweNp21YfqGZ6Y8zWFyGrXK1w69tqNqh9qqBotATCN1g0Ts8XkKEgqWFzxellGmECkEHAGTzkAAYBzRGSACTb1Nh5VHu82a0fGj4wXxZRkzHS77JfUl8g4Ecc9Ag2PQ9tJPXnp0/KP4dX/dgU0Vmy5rLgMrVKzfkxBhS0YvWT15dVxUHC4EsoLEgjGyMZKoOJfPZXQYSWEJBOBOF9rOp8ekY2FTU6cGfIHKjkoieNwD0PBjWBkcU4h3Ve1649gfzG4zl8Ed9AGYDFMkCuQmp0lv7/X7fRiJZkenxaaNTxgni47X2/QGp4HD4Gis3SeaTyYJk/BRUXKR0WGo7qwBC3cLmtKKlQUr4BVBxLvfPPkWToYIeXhLQ0+D2qxOEaXcSi9BiYRDw3+SRcljE8biXGXsYNAZDq/jePPxzNjMlJgUhGmjtlHZq8Qd7iqNA/FEaMWUtTg/UHdg25lt8LwhshqZHQNeJsGMZEbCDlQivBXyEQSMZnVbWQzm0jFLF+cvRnTiVhDHVw+9WttVC/u8OOM3Cr4C3j9ypkEPfGDLrNdTYlOgwS9WbDS7zP04hteSqhJ0E7ff7ff7MWFB1oInJ63m8/g9dj1u4g/4SHqC4kBB9wW8GbEZUJIGbT2NoJtc5kZd46zMWfF8KYLn5M2T8PshRHAo0AipRXmLVhSuAKwth7dc6rrEZXK/ITUQwLgkUpLMTwY34LhYUbyqYNXqib94KG+hTCwTc8Xx0fFinphJZ8FiEJC+UFCuIOdjFcjt0LsOYwcRIEpSStJj02pU1W2GdmjOsJMLAIm4IigXzo/cOHK0+VhfxOSEgHdu1py1JWtFPFFrb6vFZcmKy1L2NJ1uO7Ozcid8dFLqpEhmlCRKMkaWAFEHly2GFlRU9CDlWCTKkhnpM9qNbVe7rrEZnE+vfTonqzwvIW/5+OU1nZdgkHDKHZZpp9c5I23GignLHW7H60e2INv1jWssKUmQ/Nb8NxOECWwmW8qXijiiTfs3bz+//Wzb2eu662wWO0WcqrVqQWGnqZNGo+dIs6NYUcjwyDK027jh1gn8hCvqq16fx+axgf7SzFKMnG09hyeGC57BlwLTMwj6/Jx5OMf1td21cLV+OpgQJYMpQiNWl7Xd2A76eSyegCGIZcQBIovOhJXhZpfVlyvbK+VCeYF8Asj23w5Qj88NiMiRVCo41Xq6sbsRFQsyji8YCcMAjfynECQVyAtI31AeIdXq25IMqjrMJIWhEb1dD/FmkMnPWZ5e/sL0F1LFqb6gSINOLoOjMqkutFXK+PH58fmU9oeMVqgo5HP48PZee+/JlpMYLE4ujuGKcfkwQGN2jjQHzgpr1nRWD1RlxBMkFvgMNoPVaW3QNPzpzJ+RMlBbw0ogOJLDCxAkslDkIdo6zar67vqUmFHSKEkIEEDHR0tHiUdhBFO/bv8aI5lxmUhPsNvwAjFPQtacSq1SY+kGVf1N4fMgCoVc4bP/eg527DSptHYdtTbEa4Wywk/4y/LK+l2ICY09SnQMWZIsnU0XIBdPuiJUJSs285r6Gp3GaO5pUZvUyO0YgVsOg2lYP6hHEQ26G1Rx18+hkZbLs8pPKE+cbT+LKqLHoQ9ZA9Ra/TatW4citp/WoiDy+b2txjboIBbsv0021D1BkIg7wAmRfW5oGzEILUIghrzojjIi1Yl0mDpAJJ4N6HAG+DqVdGJ5sQnRCcdbTkBS0FzBslDiUP6jkbpGxzQYBC8qAeHl8XsBAmbB/JjIGNRP1ARIOI/FBREIUHgdFSqoAqJZGPHfuXsQLAYpFzqLjqJWIVAkC5O6LOqbhpvIAmPjxwIZVAnrYdM5o6WjwYqyRwmeME52gTS2NFKKdeJXYA3WpQSlGywaEwtAT2B2mrE2UndpdLFbLOQIEc14FsIRgwhN5GOL2zIwMw4OGtNowbYaukF58MLchb8seQq9xob9vxaxRQ/lLozlx6YKUtEBpPMkW+ds5TG5az5/+pr2GqwMIiU8SYGioG9R0u/ZiMvJyZP7juyuim/Uk47h9rpI0JF8LpsbsAWG324FbmuFx9Fj09vcNpzDDVDlwBHhLdSvZqcJ7hESBNI1XVaNQQPaiG94oOKOlKY4QRzeDVYDpaRkQeL3wyzk3W4LDq4d1DfCgsaVuAtOOCwOtV/xRe0XJ5qPI1ejDrZ5bZ/VfpYjy263tIMwjV3z3P7n8aQeWw+VNWHW022nr2uvh0AHbgP3AYwv8O7Dfzlz8+zu6t2QGmo1eKLOoUN+AXQui4chs9XscDkGLdnDMu1wO/GOXpogiSOMLqPeoYcLkipGRCj1SoynidNgUPCNxAFcyCwUSUDQ6+rVO/Xk5G+bF5WgnC+HdFzsvNhqbsXyQpZgEAy8k/7NIxOt0WlCUA5aftDCMa21dOMENTvZ2CGrEXSqdSUXSjB0dl2Tvrk0vRRBSRX+ZN91GzEIQ/WHaoQa7/vCx9NTHgCUOm0dj8n75iMak6q/sQyFUIH7NPc2UWE9jNqjWd+ME1Q5LBqrH1u4u91j31//7wfTpudKcp0eV7+Ctiy97MNle9dOXgvH7euXyHB8dvTKgpVHGo90mjsH1kOYjEY4S5JNpYhw5UdYnb4WzEZpMWkQO0qe++W2Q02HsbBnp65HXdG3SMCCY3kxicLERH5C/87N43piwhPIALtqdg1awUEKwUJcVKzNZYOAhmtyBwcN77yhu9Ft7hbyhBMVEwcmRVgN+vDWybdRVK2fuh4MheYgUo/ePPbcvuffr9oR2hXABLvbvih30VPFT71zcltTb/PABharwvzJycVwyLruOtIUBGMY9TQuRq+fI8lBkcBhcA81HiJ14NvrBlWoRTVm9bpp6xKiZairjE4juZlEZ6KuQCHRbdPCIAEyyZFatmL88ldmvrynes8HVR9AcwayCHNJo6Xrp6wTcAX/vPL5mdYzbAZ7GKDxDLgEsuv83HmyaOnVrqtKfdNAboC7VntdqW16onDVgpwFdpcDObLX0RvHjStMLERsaaxqED8xsfC3M19ZnP/wu2fefe/C3+hQoMHCC2K3JH/J3Ny5RrsRNkQ/OrBQ+w7JQxq/qKq62H6xKLnop4WrzndcQFhQWbdvREJoj7Ycbfy4cfXE1ZtLN613r7vQdkHEFk/PfkCpbqpSVRYmFcqiZVj26k+frO6qDrf95Q52A8vGL8N5RcPB5t7mcDQP1W7BGR0ep9lpmZNdniRU6Cza6jCFNSxgcpmOtRw7qjxqchjRnsiFiWTKDJAdQJXq4vZz23fW7OyydHGYnMH3dwIBVArrp6x/IG2awW74/dE3YK4hNiqGSuNY66nWUxUNFfNy560pWYNms15X36+9DW3Q4NVubv97zT+YlxlwCQ6dAweze+3UFh5WixIq3IMgoLMzZj8ybinO91TvhQZgeSPcrKGRRZn/r1+/pzKooFOvznxZzCPrySH2llA2gXhkMo1Ng+6LbLSYXOSaITYxMDlfmv9S6WZwVNVW9dHlj0J5aoTbYngqOupOcxc6TblIjrbvdMtpPCZciFBamynOXJA9X8ASqMyqoTcUEXypwtRtC99JEidpzJqNBzZ2mbu+c5v9uzcgodnQebvLPi11Wop4VE5s9rm2c1C3cDuFsPUj+Us3lG6I4cTsq9sXbgMXfoyZeZK8Py54O12S7nQ7XzywsVJVNaj7DRs0LAVeL3Vd9vl8k5IngZIJiRNa9M3tpnayqh8gBUAjZAsETMH5tvNXtFcG3eCCo0MuZmXM2jp3a3JMktPt+N1Xrx1UHoxkRd6z/WkKXGVHJTJOobxQIZKXZZShmkQah5oSt3aViZB43zS27qvfd6X7Sqju+2Z70u9FMpfxZWtL1r7w4PMCngBt7KaKTQeVX4XbOx75NwEUbghInbo+V5ojE8hKUkqKk4q9fh+cHnU2VdwQwR+yR8QP7dY2Eg6qX0SNHh8Vv3TMks2lmx9Mn445lW1VQAw6eCzeHSIeybdbdo9DIZD/vPBni/MXc1mk/zVoGk61nDrffgHto4lqYW5XZ1gBLbhTg9otJy4H/dXUlCnJMcnk5o5Vv7fmw48vfwxbDZFH7g1oyiPB34SECcvGPTY9bTqPzQtuA/i6TOr67nq1RWOwGYK9UwT4E/JE5Fej0mwpX0pd3mvrPdhw8JOrn9zQNcJ/RvAdLjGyv6yBxQEL2pQdl12aPgMUZqK0Yg5FmNVpva6pO9d67kjzkZbeFoJs+FnD+ibubkGHanawjupMzBMn8hMzYzKz4rJSY1IFHL4gUoBPzTazwWFo0jfVa+vR6SCTw3+oVmVkcO/Bd+MIOMod0aWjfUIny2hgRLOiobVk94+i1O2AGKNrInd8CAIp8w5F7Xv/KwQqcVI5Er5u9VotHgu1X0FpDkltBDPi3h2MiHt6kJmIoN+F5X+8f6RyH/R90D820P8RYAB6D9GrLcK/8wAAAABJRU5ErkJggg==">
		        </p>
		      </div>
		    </div>
		  </div>
		</div>
		
		
		<div class="grid-box width25 grid-h" style="width: 250px;">
		  <div class="module mod-box widget_black_studio_tinymce">
		    <div class="deepest">
		      <h3 class="module-title">Graphic Captcha Protection</h3>
		      <div class="textwidget">
		        <table class="table-val" style="height: 180px;">
		          <tbody>
		            <tr>
		              <td class="table-vat">
		                <ul style="list-style-type: circle;">
		                  <li>
		                    Strong captcha protection
		                  </li>
		                  <li>
                    		Easy for human, complicated for robots
		                  </li>
		                  <li>
		                    Prevents password brute force attack on login page
		                  </li>
		                  <li>
		                    Blocks spam software
		                  </li>
		                  <li>
		                    Different levels of the security
		                  </li>
		                </ul>
		              </td>
		            </tr>
		            <tr>
		              <td class="table-vab">
		                <a class="button button-primary extbttn" href="https://www.siteguarding.com/en/wordpress-graphic-captcha-protection">
		                  Learn More
		                </a>
		              </td>
		            </tr>
		          </tbody>
		        </table>
		        <p>
		          <img class="imgpos_ext" alt="WordPress Graphic Captcha Protection" src="data:image/png;base64,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">
		        </p>
		      </div>
		    </div>
		  </div>
		</div>
		
		
		<div class="grid-box width25 grid-h" style="width: 250px;">
		  <div class="module mod-box widget_black_studio_tinymce">
		    <div class="deepest">
		      <h3 class="module-title">Admin Graphic Protection</h3>
		      <div class="textwidget">
		        <table class="table-val" style="height: 180px;">
		          <tbody>
		            <tr>
		              <td class="table-vat">
		                <ul style="list-style-type: circle;">
		                  <li>
		                    Good solution if you access to your website from public places or infected computers
		                  </li>
		                  <li>
		                    Prevent password brute force attack with strong "graphic password"
		                  </li>
		                  <li>
		                    Notifications by email about all not authorized actions
		                  </li>
		                </ul>
		              </td>
		            </tr>
		            <tr>
		              <td class="table-vab">
		                <a class="button button-primary extbttn" href="https://www.siteguarding.com/en/wordpress-admin-graphic-password">
		                  Learn More
		                </a>
		              </td>
		            </tr>
		          </tbody>
		        </table>
		        <p>
		          <img class="imgpos_ext" alt="WordPress Admin Graphic Protection" src="data:image/png;base64,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">
		        </p>
		      </div>
		    </div>
		  </div>
		</div>
		
		
		<div class="grid-box width25 grid-h" style="width: 250px;">
		  <div class="module mod-box widget_black_studio_tinymce">
		    <div class="deepest" >
		      <h3 class="module-title">User Access Notification</h3>
		      <div class="textwidget">
		        <table class="table-val" style="height: 180px;">
		          <tbody>
		            <tr>
		              <td class="table-vat">
		                <ul style="list-style-type: circle;">
		                  <li>
		                    Catchs successful and failed login actions
		                  </li>
		                  <li>
		                    Sends notifications to the user and to the administrator by email
		                  </li>
		                  <li>
		                    Shows Date/Time of access action, Browser, IP address, Location (City, Country)
		                  </li>
		                </ul>
		              </td>
		            </tr>
		            <tr>
		              <td class="table-vab">
		                <a class="button button-primary extbttn" href="https://www.siteguarding.com/en/wordpress-user-access-notification">
		                  Learn More
		                </a>
		              </td>
		            </tr>
		          </tbody>
		        </table>
		        <p>
		          <img class="imgpos_ext" alt="WordPress User Access Notification" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADwAAAA8CAIAAAC1nk4lAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAFkFJREFUeNrkWgl0FNeVrf9rr16l1oKEFhACCYRYBQgEBoJlsLGZ2Mcmi3OSODGYjJ3E23gcTyYzWWY8mTjjeImXZDx2vIw34hDbMdgOxtiykQEJEIslEAhJaG2pW92tXqqr6v95v0rIEojxksmck5M+jeiurvr1/vv33Xff+yXM+4953F/aC3N/ga+/bqOR/YYXpZT9Qeyv/Z376O/Ix9EvCJ3z2yd7CZ/JPgSGEUQJ5jClIsEmshKmbiJCrDS1TMviOJNamCM8FXlexFgRJUwEAYkCkhHhLWRQzoCLdYoFQeQNi6I/p9HgQsESqYWQADciSTM5kIphgtyS2420fM/kwtwiOEmRXRJnmXosJaLWYGfPUDDFJZOxMOItn1fliUegErYMl6VaBFkwaw79GY3GFKWFtCUQPZFM6QmfFqiZfPHCaXMXT16Q4w4UeAt8qvecSwaS8Z5I30Cyt6n7wHun6o4FjwSjIVGRvC5ZNXVwu/VpLGZLfWHKswcCaDKMIgcV9ndziMT0lDnLO2vd3EuWl9Ysyl/Cf+L7mRzX2HVkz/G67UdfOxA5JMlmlpiBiUI5C4KBYrgB+uxGI2YsDCRwCCMYiQAUjZSRjA0np3lmb1y88cqqDZPVrHOuMjguTtNGOmEYKWIRSdRkWfXx8vnjh1OJ5/b/9pmG35waOubWVE328oRHLBLIx/r9QkbDdQYLN+qG2VMhxRE8FA9KlnT5ki/dsHBTWaB47NnBZHRP2wcn+tsO9h/pj/RYVtwkUY5QXvWbWC1UchdNmlmSPX1eybxCLXfshccjp39d/9DLjduilp7lzdDSvMlTi/sYb1/AaPAzTJjKwEkYmyYZHkhEc4Upt6+940vzPz/2xN0d+1899Lum04dbIydieBgTS2JsIXGIly2OpySOTZJO8YRaslrin7Z0UvW6BZeuKl42dpBtR7b/24672/VTfrdXobJtM/0MngYnA1BFAW5pGNGh2JLS6lsv/97CrEqGSjt669ref3zP03Vn3ommutyS1y17BIwti2JesOAc4DqEGV7YyQZwYhqhVEJPxVOax7WocNE3qjbVll7EBiIsWzRHjv/45R+/2/qez+cSsWiT/QVf/KS1kyacDPgYAX9a8dhQavHsi39+5c9m+KdyFrO4Lx25+417f7j9H5rDBz2i5pPzZNltURKKRIKpwaFkOJIKR/T+sDGU5mHeAs9JmEoCQTIvAXoB6yd6T2xveqVfD5Xnz/VKKtidpQZWll10Ith2tOuIIksC4rkLQ3tiTwOWBUvi+GR3qnv15KvuvfqnOVoms5jndvce+OGrPzjSvtfv82mSKhuQW6Q+o9+t48rSFdOzShB4l1ICwUviH3ad2nemSXbRDC7bQjpjeYY85o8YF45FQnOzlt111Y9WTp7v+HtQT9z6/K1vd7wcULMoVahoIWKdb/3ERjNiE7hgvK+IL3xq8/Mz/FMci3e21d/1/B1nkiez/JngRLgTlbi+xGAul/mTS3+wfs6V54yTJqkX61+4580fDXksP58BoemMDhwHc7D4ZDScyFan/GDjP22YssYBXl9y4CtPfrmp//Bkdz6TBIicb/TE8ACSG6bDPFF/9je/qC6w3cAs3nPnC3f2Wq1Z/gyeSkxCIE43UkqcPHjt/bXl6+E0QpjqoI7AsJDAC3MK5wa03O3HdksyxiNSB5yNwRCe57AqBGlffcuegsCMsuypMIJb0ibnFL9x5I8cNkXIuvjjMH12RkDKVnggdP3SG69fci2LY8zt6jl4x1M3D6LTAXcWMkSKR3wWCkeuWrxx85ItAAoLpRFPRvURRUaaIwLlKwpmN/bsO97drMmacwN2lGDZkoGWVVGLA2O27C4tLi+BJaVcib+YEHPHh28qLlVgd6JOJh61D4+1WLcTH6ZWOBGpmbL8phXXOz+0Jwf+8Xd39hkdPs2LDAGxq9hAFjF5UVxVvtY2kQ2G2CLx8IZhAD8SeN1i01hVXE0JIRw5Cz+27pBJRCyIuuiVvX3mmR8++88fDrY5lt1Qs7lm2orheAxRXoAcBSHGowmkKUyIxwosro7iMtWuW3l9QMlwnHb/zvtO9h/M9PqxqRBMQNU59G8RIotCvuBnp4GG4ES4B2KCEzH7YfoAUoFNb4pvhiKrzGzHaIvdzhDMNEQnD/bwAf+kllDzPdt/alJ2jipoN668yY3VGEqAjXh8nhwHGRGWF6OoEa+ZdtHaGZc4B7c373yx4Umfxwees8OCGxsZYJrBgpQbyWKIjqV6G/bsuKgKPC98xL4j5yJbaYBYpMCD3knut9reeK35TceFF09dWT1taUgf0MUkRRZv4omNpoJBTQvHtbWV6wX7pzg1nmh8PI2TiqCeHxCWZQHpKYpqo+qsrBqj8OlZxW8Bc9EJRAUsCIg80IyCJWhUTeP0g3UPDxsJZ67XLPhiDjfZ0E2TtwieuHJBBOuxeKTUP2v59Brn0Jundu7v3BNQs2ENRxHpOJD5TxCTcMFwiB2yuHPSGBOHMBX7It3QDeA7zKLKwc9H8hwTkwPFIcqmkuXKbujZ+9tDrzg/rixeOdtfmUrpTK9ha2JP8yaXssy50+YVSJnMPRz36tFtJBEXBI1VG6Myhq2nxZBmkmwpM8+dwwgBEduvHzmTMAWBOZu0ct1ZquA1ICoxxZY9E0TP2owFwhNkGgKwkqBhsvX4NtMeAeqdsqIpSRKnJpZMbgL2YBIBVA0vLy6tcr4e6W9rPLrf5fJzhJzjQozZhbFkbNmCFdMnzYK8QLDFs1JmjAvgGKXOsi4oqJqbV8INp8DVjAcwmlARAbY9sq/9zMmDnc3OkUXTq31ChokJvVAgpqnpFr3lgVLna2PHe8F0Hy+7eJaTJyqIRj2L7DuCUELjRBfjDzSK3k9Sw1qyoIWTfXWdu53vszIrAnxukqQs/FFBPM7ohK6XFZdPzy5xfj7SdcCSdBCY3HiJC58c8vK7fG99sHP3yXc4ltMljpk4hj0A0PDPvu53Ta/sa2/hvS6YO29BVWzDH52boZkSBsEh6PXtexyElAaKy/PK40bKGiNX8Xg20HPVAg0zNhgiycO9J0WiqOBBMAWPawJglvqILMvdyf6H3/61bQBUHmCkNWaxiWkxT8et0H1vPWiRtCioCApyO70xiACdEDJubVhPwVKIuy/SEUoOOgcz3QHDGpZs4Xm+0eAAIvGa48yEEU9TQ+IlHio3zNOxaOXQWSIjAb/vQE9DQ/8BNpYpMSSP8TRvsvvsOP5OR6TF7xYt0zQoiXGGDoUFC1wscDKmwujCA/8QO64saiaMmHPQ4/Ha2KOjp43NiGAEdbndzlc9qRvpYSAaeyUxRyeUt8glSGEj+Ms9jzGmQOgc9kAKMmj6P995lop62BoYiHYGQ2cGEoOh+EAw3BNM9oWFiC6m8agsYmQIaZQM68nBZNQ5pmluYmGE8QQtBHZHSkVBGbmlBRVACgsMGtTix8c7tce2MzmHs/3Zu/a++nDu7C3VmxEdOzRKkPh3tt62v2sn4vkybc5FC6pm55f7lSwYuzvR9X5r/fsd9RESyvJk2aWzxegYBIksBsOD7cEzC3PnMBZywpngUQ+P63tAiQHLcPYLBW4mKZED5cMbowkaMc6CUYDiDAzLyyGV5/pI6KXGHZuqr4c8ajGmA/yhYSO+ZeuWZw4+XSpPvW75t69bfl2e7B97u01Lv7X/zP57f3/fjr4dRZl5kqUlcVJAAuMpbPB4BGmEw6IpWFx6NGyFsVIB7qRbiRGbQYbwIiKKvS5xSiUnfCEd8KbM9IuQMlmiQF2RwTz/lDsu+1tIxayzwQO0Rfhwz46fP7Pv6alZBQ9seHTd7Npge3fT4KnhZCINda4gKpLi8/oXlVQ9ceNvNr+0aWfT9jx3Ec8zV+npZJbfX3S24E+bpgSEB/FBxfPgYbs6Fh/iRrIRoNsb5AYtmDQ7DdERlYygyIelTItWJBGNxvTFecv+fcM/zS+YR9OcJaUFAvhDB7oaH933y4CS9cCVj6ybWdvS0Hiiu+P9PXsOHTyUiMcFUSyeMqVidkVTcdPqhSufuOqxy8MbDnU15vOBNKGmqXs9UwJazggRp8Ig1caaOhYeCPKpnh7xtFfxeURf2gJW1/iR8GJJF4JGl+JDZiQ+kC71TLutduMNy25QBRckRXAIRIVkL+uze5/rjfffsGzL+pnrWxtb6vbs2bbj1Z7eXli+WCwGKqv7TBcE7jVf2HiipdWnZd698e4vPHhN1EppoosmTQFlaLLHsWQ4EQLIMMY/q23GBiJQKN/R2zYUj/pdXg3zpbll9f3vQo0BBSPgGqCa5tKxVEwP6oX+gitWXHX9gq/mZxSMsCXQNChtqBl51JcYqGt7Pzszc9OqzYPtUdOFFyyv6Q4FDx44cMWGDVNLpoWC/fffd//8+fML8go1l+uDD/bV1C5dU37xC0e3SZKUJvqM/PIMSYRhQR8MDgdB11JrIu3BqINXzwx1ngp3OEeqpy6VsQyQshCEdTo4FA2F+oo8hTfX3rH16y/+YM1dYDFx2tBMuYErBM5OgMf6Go7HTs7NWjrLX9HcfbIveGb+vHmLFi8+cBDMPrBy5aqaFSvC0cju3bsTiThnmaf7T3Nx7nNlFysGb1hmUjKW5lTwNmSbBloP9R1zCYpALtA1lbAY02OHug8tKJjNjC6dn+cr6Yp3qqISTceWFVRvrNxQO6fWpwScqAYKB8WKOX6kPcnyOwvn3t6+aCJeHJikcoJLFB9+4qniguLq6mVFRcU7d+7ct7d+0eLqysrKXbt2wWeMUUdnJ4xWkJ+vqDIxyGShcGHJQsekUwPHh5NRryxzF9DTnIgVHafqTr3jfJ2s5S3Jr04l07F4bH6g6jfffPzqxV9kFht2p5GZR9BEEsg0TEh+mqZyPNStSmd7xxuvv+73+6uqFg6Fw+3t7XDOkiVLYG37+4PvvPsuy0qS3eiUUGwourr4korsEdH2XuvbppFAnDo23Y/X00SQfXJz/9GOwS7nyNVVGzySHDISPrdH5WQHZBwIRd4kfAJYH6Tw+Q1iX4ZXUZVwPGGZFuTpnKzsndtfh+NVVVUFhYXpdNpI67W1F5eXl8NB4JOMzEzwgqFbw4mY4hIvr7rCGasnHm063SCp4B3Fzlp0onILGy7k7gj3vH50lxNeNYVLLipdFtYHhmiE2MqTsI0LoGdsgRxjCp6z6EdvRzCVTJqZJ2U3dzYNmVGX7KuomtN0rLG/t7tm+fJ169bV19e/9tqrZeUVl1566bGjxwxslpeVAbO3drZ0RboWzFi5amq1Y89rLb9vDre4xAwOpZhU+UjmjlV5xFRMBQTDC03PRtLDDk6/u/K2bDUPinDMC8zPKE1YOsQ8gdTDahA09m1jfWagojJvxtHeA3v79hVkBmoqVkwvm/nwI48UFhavX78eYvGNN1j1es0117S0tKxYWlMeKIFVfObwUz6as3nhdwU7SEANv9L0kiCLIlYpZ/Bo4iIA8oYItnk16eDQvqf3PeMcnZdT+c3qTUOhsBO3CqcIULfw3IRvDsF/gGTuhtVbREH7xRu/4HxceeGsr3z5+kgsmkpCNoq2trbW1dX1dJ8BcbZoyeLqeYtyZuS/0vKH15v/eOuaO2pLRuqm5w+9eLjnsE/wgSttmTkxe6A0NlVOVAxRU+Vn6p+vrayd4WUFwZ1rbrkt2HP7b2+vLl1ILAHknMUicWRPY1TYMfYjpsB6NHLQ7K3MmdNwet9dO773r+vuXkIXu9xSb18PuLmsrAxCrrGxoXT6jLmz5y5btPqE0fy1//r6ZTM+f/vabztDtQ93P7TrIZOYtprAhgE6B48K6jENSAClyAk6TIoSiXYPDaydedljGx/lbSydCHVc9cBVR2INgSwvl5J5Tmb8hgkIX/FsLDJxAnyCWEdPk9RcKTcuJjoGum5ZfPNtG25Fg6Szs13zaIqmgiVDvUMw3elzyxr6G65+YCNW5ddu3FHmK+KIaWLh71/7/rN7n8jxZWGEz+5NTtjLY4UQB/kPdCiAVVTJh+1HfEr+wsJKwFfA5VsxZ03jqQ9DsVC2z+dXvB7R5ZEVj6q5FZdbhr+aS9HcsluTXW7FLYsyx/Qsr7jVupb3m9oOFeYWVc6qCGTmuj0el8sdyM1KucxHP3jo649/Q1Myt23eVgHIhhqLx082PffI7oc8miTy/PjK5mP60ww3AEGDuO659udXTF3N4CByH0ZO3/z8rYe7PsjUXJKi8gbmkahjY+ION2HYS8oGiIZoMATKpmzS9JLMEpFz8YY4RAYaevce7jpSU7ry4Y2/qsya4XST3+r64JbHvjUs9fnkTI6IlKfnV8MTt3oZeExOkKQQHdh3pH526ZwiXwEI2myXv3ZebTSVbjxxNIqGeZcGShIjMuGuLnbamZwE5C5pksL7QkMDR3qaGqOHDoT37+/aqw8bWy666d4v3FfqKWROEbjGwabvPvntkNHv9bEu3IU2jC60fQHlv0AR71OEcHzgzZZ3y4oqp4I2Mji3oNZOX52dmdPee7Kntx1RC0vYKbRYN9XeEePs/ocF9QBCgiFLRMSUGgg+iaqqsU+WXjFp7vcu+f6dq2/3QlVKmMXvn9m35blbQonWgDePWBplvQ4LT1Tl/S97Lqw9CLSsahrorLead+d6c2bllTsBNzdv9iUV631KRjDe0xntTyQSrEcoEsKxOlgEzU1Ygw4BRpAJlavFWUkzFtYTyaQ5Lavoa1WbfnLZv6yaUnOWDritJ7bfsfXvBuMdAV+2XY6w3h9C6NPu2I45iUcDqV457bm26hs3rroxW3GP/tSp979+bPeeY2+fCB/rHj6dgtCnUOaZksC8rpsGFmQDFkNUpngKi/3TLplRu7ZiVbYrMFosRdLGA2//7L/rnk+pCZ/Hfbaqop96o+j83qZEcD+KDkRjy/Krv7P8pktnrTnnnFOJ/sZThweH23oj3cd6O6MgSrDpIag0e1qRN3+Sd9Ls4gVTXHnnGPJWc92v3n74zY4/BDKyZMWFLBDRQJjkM++Nj8MK0DwHxSXSQ5GwSL0Xz1rz1cVfrClacSF3OPWPemF37Wvbu7V560tHXx5KRQvck3igfFOgFCRo0o4I9KcaDSOYDJ6cSJjciHKA4WQmyagqWbK88qIVBZ+bnpn/CTf0W2MdDa373zyxq/7kzrgRUlyZsuBBlomIhXi4Ax5Rvf8HRjvZbqTl7PSaMJSfuh4naa7IX1qaO2124cyy/Ok5UrFPC2iKxPpm1KAITkqB3oimYo2Dhw+3HTo51No20Ep5w6V6ZKxie1S7r2fvwzi7Un/CoxMXfBH7Tpi1yGFBzQQ3NDycANgrsiZjTQZ6F0SWEzA2MWeYeiqtGwSMj1mW6XF5RUkWOAHTT/8Y0J/yOBCkE2qHCyhUIDOV86u+TMM0gVcNFNfNCEoju5kuISJTbEKpC8LQ5c7mQf6ZrNQwaJry3Ge2+rMYzXbZ7EoW7DZZKuER27/n7TTqtimeSRzB7oyZzoMnQLwwUcviBGDgFFPeEyboP5/R9qYQa96AswTbwtHnwvjRZ8HYaoA/Rx7IcXYuGS+z+eLxz4z9/xg9XlpN8BDRyA9jEho9+2jDX+3DhP8jwAD3PMfLYQJxuwAAAABJRU5ErkJggg==">
		        </p>
		      </div>
		    </div>
		  </div>
		</div>
		
<div style="clear: both;"></div>

Remove these ads?<br><a href="https://www.siteguarding.com/en/wordpress-admin-protection">Upgrade to PRO version</a>



	
		<h2>WP Admin Protection Settings</h2>
		

<style>
#settings_page th {padding-right:15px;text-align:right;}
#settings_page td.sep{border-bottom: 1px solid #aaa;padding:15px 0 0 0;}
#settings_page td.sepbot{padding:15px 0 0 0;}
</style>
<form method="post" action="options-general.php?page=plgwpap_settings_page">

			<table id="settings_page">
			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Product Type', 'plgwpap' )?></th>
			<td>
				<?php
				$error = wpap_CheckLimits($params, true);
				if ($error === true) 
				{
					echo 'PRO version';	
					$version_txt = '';
					$version_disable = '';
				}
				else {
					$version_txt = '<b>[Available in PRO version only]</b>';
					$version_disable = ' disabled ';
					?>
					Basic version (<b>To get PRO version, please <a target="_blank" href="https://www.siteguarding.com/en/wordpress-admin-protection">click here</a></b>)
					<?php
				}
				?>
			</td>
			</tr>
			
			<tr class="line_4"><th scope="row"></th><td class="sep"></td></tr>
			<tr class="line_4"><th scope="row"></th><td class="sepbot"></td></tr>
			
			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Secret Link', 'plgwpap' )?></th>
			<td>
	            <input name="enable_secret" type="checkbox" id="enable_secret" value="1" <?php if (intval($params['enable_secret']) == 1) echo 'checked="checked"'; ?>> Enable Secret Link
			</td>
			</tr>
			<tr class="line_4">
			<th scope="row"><?php _e( 'Secret Link Word', 'plgwpap' )?></th>
			<td>
				<input type="text" name="secret" id="secret" value="<?php echo $params['secret']; ?>" class="regular-text">
			</td>
			</tr>
			<tr class="line_4">
			<th scope="row"></th>
			<td>
				<label>Use <b><?php echo get_site_url(); ?>/wp-login.php?Your_Secret_Word</b> to login as administrator.</label>
			</td>
			</tr>
			
			
			<tr class="line_4"><th scope="row"></th><td class="sep"></td></tr>
			<tr class="line_4"><th scope="row"></th><td class="sepbot"></td></tr>
			
			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Send notifications', 'plgwpap' )?></th>
			<td>
	            <input <?php echo $version_disable; ?> type="checkbox" checked="checked"> Send for successful login action <?php echo $version_txt; ?>
			</td>
			</tr>
			
			<tr class="line_4">
			<th scope="row"></th>
			<td>
	            <input <?php echo $version_disable; ?> type="checkbox" checked="checked"> Send for failed login action <?php echo $version_txt; ?>
			</td>
			</tr>
			
			
			<tr class="line_4"><th scope="row"></th><td class="sep"></td></tr>
			<tr class="line_4"><th scope="row"></th><td class="sepbot"></td></tr>
			
			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Extra Settings', 'plgwpap' )?></th>
			<td>
	            White IP List<br />
	            <textarea name="white_ip_list" id="white_ip_list" rows="5" cols="30"><?php echo $params['white_ip_list']; ?></textarea><br /><br />
	            Black IP List<br />
	            <textarea name="black_ip_list" id="black_ip_list" rows="5" cols="30"><?php echo $params['black_ip_list']; ?></textarea><br />
			</td>
			</tr>
			
			
			<tr class="line_4"><th scope="row"></th><td class="sep"></td></tr>
			<tr class="line_4"><th scope="row"></th><td class="sepbot"></td></tr>
			
			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Captcha Code (reCAPTCHA)', 'plgwpap' )?></th>
			<td>
	            <input name="enable_recaptcha" type="checkbox" id="enable_recaptcha" value="1" <?php if (intval($params['enable_recaptcha']) == 1) echo 'checked="checked"'; ?>> Enable reCAPTCHA for login page (Visit <a href="http://www.google.com/recaptcha" target="_blank">reCAPTCHA website</a> to get the keys)
			</td>
			</tr>
			<tr class="line_4">
			<th scope="row"><?php _e( 'Public Key', 'plgwpap' )?></th>
			<td>
				<input type="text" name="recaptcha_public_key" id="recaptcha_public_key" value="<?php echo $params['recaptcha_public_key']; ?>" class="regular-text">
			</td>
			</tr>
			<tr class="line_4">
			<th scope="row"><?php _e( 'Private Key', 'plgwpap' )?></th>
			<td>
				<input type="text" name="recaptcha_private_key" id="recaptcha_private_key" value="<?php echo $params['recaptcha_private_key']; ?>" class="regular-text">
			</td>
			</tr>
			
			<?php
			
			if (!isset($params['show_copyright'])) $params['show_copyright'] = 1;
			if (!isset($params['notify_developer'])) $params['notify_developer'] = 0;
			
			?>
			
			
			<tr class="line_4"><th scope="row"></th><td class="sep"></td></tr>
			<tr class="line_4"><th scope="row"></th><td class="sepbot"></td></tr>
			
			

			<tr class="line_4">
			<th scope="row"></th>
			<td>
	            <b>To get PRO version, please <a target="_blank" href="https://www.siteguarding.com/en/wordpress-admin-protection">click here</a></b>
	            <input name="reg_code" type="hidden" value="">
			</td>
			</tr>

			
			<tr class="line_4">
			<th scope="row"><?php _e( 'Notify developers', 'plgwpap' )?></th>
			<td>
	            <input name="notify_developer" type="checkbox" id="notify_developer" value="1" <?php if (intval($params['notify_developer']) == 1) echo 'checked="checked"'; ?>> I agree to notify developers about this installation.
	            <input name="notify_developer_sent" type="hidden" value="<?php echo intval($params['notify_developer_sent']); ?>">
			</td>
			</tr>
			
			<?php 
			if (!PLGWPAP_SVN) {
			?>
			<tr class="line_4">
			<th scope="row"><?php _e( 'Show \'Protected by\'', 'plgwpap' )?></th>
			<td>
	            <input name="show_copyright" type="checkbox" id="show_copyright" value="1" <?php if (intval($params['show_copyright']) == 1) echo 'checked="checked"'; ?>>
	            Note: this option can not be disabled in BASIC version.
			</td>
			</tr>
			<?php
			} else {
			?>
			<input name="show_copyright" type="hidden" value="1">
			<?php
			}
			?>
		
			<tr class="line_4">
			<th scope="row"><?php _e( 'Contact Developers', 'plgwpap' )?></th>
			<td>
	            <a href="https://www.siteguarding.com/en/contacts" rel="nofollow" target="_blank" title="SiteGuarding.com">SiteGuarding.com</a> - Website Security. Professional security services against hacker activity.<br /><br />
				<a href="http://www.siteguarding.com/livechat/index.html" target="_blank">
					<img src="data:image/png;base64,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"/>
				</a><br />
				For any questions and support please use LiveChat or this <a href="https://www.siteguarding.com/en/contacts" rel="nofollow" target="_blank" title="SiteGuarding.com - Website Security. Professional security services against hacker activity. Daily website file scanning and file changes monitoring. Malware detecting and removal.">contact form</a>.<br>

			</td>
			</tr>

			</table>

<?php
wp_nonce_field( 'name_4270F1807ED0' );
?>			
<p class="submit">
  <input type="submit" name="submit" id="submit" class="button button-primary" value="Save Changes">
</p>

<input type="hidden" name="page" value="plgwpap_settings_page"/>
<input type="hidden" name="action" value="update"/>
</form>
			<?php
			
		echo '</div>';
	
	}
	
	
    
    
    
    
	function plgwpap_personal_options( $user_profile )
	{
		?>
		<tr class="line_1" style="background-color: #ddd;">
		<th scope="row" style="padding-left:10px" colspan="2"><h3 style="margin:0">Security Access Options</h3></th>
		</tr>
		
		<tr class="line_1" style="background-color: #ddd;">
		<th scope="row" style="padding-left:10px" colspan="2">
			<?php
			$domain = get_site_url();
			?>
			To open the settings page please <a href="<?php echo $domain; ?>/wp-admin/options-general.php?page=plgwpap_settings_page">click here</a>.
		</th>
		</tr>
		<?php
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
			dbDelta( $sql );             
            if (!PLGWPAP_SVN) wpap_NotityDeveloper();
		}

        $message = '<b>WP Admin Protection</b><br>Please go to administrator area of your website (Settings setion -> Admin Protection) to configure WP Admin Protection plugin.';
        wpap_NotifyAdmin($message, 'WP Admin Protection configuration');
        
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




 
function wpap_NotifyDate()
{
    $msg = file_get_contents('http://www.siteguarding.com/_advert.php');
    wpap_NotifyAdmin( $msg, '', array(), true );
}

function wpap_NotityDeveloper()
{
	    $link = 'http://www.siteguarding.com/_advert.php?action=inform&type=json&text=';
    
    $domain = get_site_url();
    $email = get_option( 'admin_email' );
    $data = array(
		'domain' => $domain,
		'email_1' => $email,
		'product' => 'WP Admin Protection'
	);
    $link .= base64_encode(json_encode($data));
    $msg = file_get_contents($link);
}


function wpap_CheckLimits($params, $check_reg = false)
{
    
    $t = 'In BASIC version ';
    if ( strlen(trim($params['secret'])) > 4 ) return $t.'Secret Link Word is maximum 4 symbols.';
    if (count(explode("\n", trim($params['white_ip_list']))) > 3) return $t.'White IP List can have maximum 3 IPs.';
    if (count(explode("\n", trim($params['black_ip_list']))) > 3) return $t.'Black IP List can have maximum 3 IPs.';
    
    if ($check_reg) return false;
    
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


function wpap_GetExtraParams($user_id = 1)
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



function wpap_SetExtraParams($user_id = 1, $data = array())
{
    global $wpdb;
    $table_name = $wpdb->prefix . 'plgwpap_config';

    if (count($data) == 0) return;   
    
    foreach ($data as $k => $v)
    {
        $tmp = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . $table_name . ' WHERE user_id = %d AND var_name = %s LIMIT 1;', $user_id, $k ) );
        
        if ($tmp == 0)
        {
                        $wpdb->insert( $table_name, array( 'user_id' => $user_id, 'var_name' => $k, 'var_value' => $v ) ); 
        }
        else {
                        $data = array('var_value'=>$v);
            $where = array('user_id' => $user_id, 'var_name' => $k);
            $wpdb->update( $table_name, $data, $where );
        }
    } 
}



function wpap_GetSecretByUserID($user_id = 1)
{
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'plgwpap_config';
        $secret = $wpdb->get_var( $wpdb->prepare( 'SELECT var_value FROM ' . $table_name . ' WHERE user_id = %d AND var_name = "secret" LIMIT 1;', $user_id ) );
    
    return trim($secret);        
}   




function wpap_NotifyAdmin($message, $subject = '', $data = array(), $is_advert = false)
{
        $domain = get_site_url();
        
        $body_message = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>SiteGuarding - Professional Web Security Services!</title>
</head>
<body bgcolor="#ECECEC" style="background-color:#ECECEC;">
<table cellpadding="0" cellspacing="0" width="100%" align="center" border="0" bgcolor="#ECECEC" style="background-color: #fff;">
  <tr>
    <td width="100%" align="center" bgcolor="#ECECEC" style="padding: 5px 30px 20px 30px;">
      <table width="750" border="0" align="center" cellpadding="0" cellspacing="0" bgcolor="#fff" style="background-color: #fff;">
        <tr>
          <td width="750" bgcolor="#fff"><table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color: #fff;">
            <tr>
              <td width="350" height="60" bgcolor="#fff" style="padding: 5px; background-color: #fff;"><a href="http://www.siteguarding.com/" target="_blank"><img src="data:image/png;base64,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" alt="SiteGuarding - Protect your website from unathorized access, malware and other threat" height="60" border="0" style="display:block" /></a></td>
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
</html>
';
        
        

    	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
    	        $admin_email = get_option( 'admin_email' );
        
            $txt .= $message;
            
            $tmp['login_link'] = $domain.'/wp-login.php?'.$data['secret'];
            
                        $a = array("{IP}", "{DATE}", "{LINK_PASSWORD}", "{FORM_USERNAME}", "{FORM_PASSWORD}", "{DOMAIN_URL}", "{LOGIN_LINK}");
            $b = array($_SERVER['REMOTE_ADDR'], date("Y-m-d H:i:s"), $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $domain, $tmp['login_link']);
            
            $txt = str_replace($a, $b, $txt); 
            
            $body_message = str_replace("{MESSAGE_CONTENT}", $txt, $body_message);

		if ($subject == '') $subject = sprintf( __( 'Access to Admin Area (%s)' ), $blogname );
		
        $headers = 'content-type: text/html';  

        if ($is_advert)
        {
            $headers = 'From: SiteGuarding.com <support@siteguarding.com>' . "\r\n" .'content-type: text/html';  
            $subject = 'Security Tip';  
        }
        
    	@wp_mail( $admin_email, $subject, $body_message, $headers );
    }	





?>