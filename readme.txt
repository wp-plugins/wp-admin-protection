=== Plugin Name ===
Contributors: SiteGuarding
Donate link: https://www.siteguarding.com/en/website-extensions
Tags: access, security, block, blocked, attack, security, hack, hackers, hacking, login, login alerts, login security, malware, permissions, personal security, protection, secure login, secure website, security plugin, two factor security, two-factor, twofactor, users, virus, vulnerability, web server security, website security
Requires at least: 3.0
Tested up to: 3.8.1 
Stable tag: 1.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Plugin prevents access to admin area without appropriate access key and adds a higher level of security to your website.

== Description ==

Everybody knows that it's easy to access administrators  area of WordPress website using standard 
login page. That makes hacker's life much easier and your website security weaker. Anyone who 
has got a brutforce software can easily access the administrators login page and run the bruteforce 
software. If your login and password are not secure enough your website might be accessed by the 
thief. When we were working on our plugin we tried to make attacks on your website impossible.

WP Admin Protection prevents access to administration area without appropriate access key. This 
plugin adds a higher level of security to your WordPress website. Even with the correct login 
and password the hacker will not get access to administrator area without special secret key.

Example: http://www.your-website.com/wp-login.php?Your_Access_Password 

Hacker needs to know this Your_Access_Password (secret key) to login as administrator.

Main features:
* Easy to install, easy to use
* Captcha codes for your WP login page (to prevent a brutforce attack)
* White IP list (these user can login without extra security, e.g. you can set your own IP address)
* Black IP list (these users will never get access to your administrator area)
* Prevent password brute force attack with strong "secret key"
* Notifications by email about all not authorized actions
* Free support by email (support@siteguarding.com)


== Installation ==

1. Upload `wp-admin-protection.php` and `recaptchalib.php` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to menu Users
4. Find your admin user and click edit
5. On administrator's detailed page, you will see `Security Access Options` and configure the access settings
6. If you need full version, please visit https://www.siteguarding.com/en/wordpress-admin-protection


== Frequently Asked Questions ==

= What is the difference between Free and Paid =

The difference only in the limits.
E.g. in free version the maximum `secret key` is 4 symbols, full version doesnt have this limitation.   
Complete list of the limits you can see here https://www.siteguarding.com/en/wordpress-admin-protection


= Do you provide support for free version =

Yes.



== Screenshots ==

1. Easy configure on user's Profile page.

== Changelog ==

== Upgrade Notice ==
