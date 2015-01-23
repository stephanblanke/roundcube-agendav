<?php

/**
 * Roundcube AgenDAV Plugin
 *
 * @author Stephan Blanke
 * @license GNU GPLv3+
 *
 * Configuration (see config.inc.php.dist)
 * 
 **/
require_once('Encrypt.php');
function log_message() {};

class agendav extends rcube_plugin
{
    // all tasks
    public $task = '.*';
    // we've got no ajax handlers
    public $noajax = true;
    // skip frames
    public $noframe = true;

    function init()
    {
        $this->load_config();
        $this->add_texts('localization/', false);

        // register task
        $this->register_task('agendav');

        // register actions
        $this->register_action('index', array($this, 'action'));
        $this->register_action('prefs', array($this, 'action'));

        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('login_after', array($this, 'login_after'));
        $this->add_hook('session_destroy', array($this, 'logout'));
    }

    function get_db_driver()
    {
        $rcmail = rcmail::get_instance();

        // try to translate CI db driver name to proper PDO driver name
        switch($rcmail->config->get('agendav_dbtype', false)) {
            case 'mysqli':
                return 'mysql';
            case 'oci8':
                return 'oci';
            case 'postgre':
                return 'pgsql';
            default:
                return $db[$active_group]['dbdriver'];
        }
    }

    function login_after($args)
    {
        $rcmail = rcmail::get_instance();

        $dbh = new PDO($this->get_db_driver().':dbname='.$rcmail->config->get('agendav_dbname', false).';host='.$rcmail->config->get('agendav_dbhost', false), $rcmail->config->get('agendav_dbuser', false), $rcmail->config->get('agendav_dbpass', false));
        $stmt = $dbh->prepare('insert into '.$rcmail->config->get('agendav_dbprefix', false).'sessions(session_id, ip_address, user_agent,last_activity,user_data) values (:id, :ip, :user_agent, :last_activity, :user_data)');
        $stmt->bindParam(':id', $guid);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->bindParam(':last_activity', $last_activity);
        $stmt->bindParam(':user_data', $user_data);
    
        // encrypt password
        $encrypt = new CI_Encrypt();
        $encrypt->set_key(md5($rcmail->config->get('agendav_encryption_key', false)));
        
        // create all necessary infos for the agendav session line
        $password = $encrypt->encode($rcmail->get_user_password());
        $username = $rcmail->get_user_name();
        $guid = sprintf('%04x%04x%04x%04x%04x%04x%04x%04x', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
        $ip = rcube_utils::remote_addr();
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        $last_activity = time();


	// read existing preferences array
	$pref_stmt = $dbh->prepare('select options from '.$rcmail->config->get('agendav_dbprefix', false).'prefs where username=:username');
	$pref_stmt->bindParam(':username', $rcmail->get_user_name());
	$pref_stmt->execute();
	$prefs = $pref_stmt->fetch(PDO::FETCH_ASSOC);

        $user_data = 'a:4:{s:4:"user";s:'.strlen($username).':"'.$username.'";s:6:"passwd";s:'.strlen($password).':"'.$password.'";s:5:"prefs";'.serialize(json_decode($prefs['options'],true)).'s:19:"available_calendars";a:0:{}}';

	// create session in agendav
        $stmt->execute();
    
	// destroy database connection
        $dbh = null;

        // create cookie containing the agendav session_id
        setcookie('agendav_sessid', $guid, 0);

        // save agendav session_id in the session, so it can be used on during roundcube logoff to kill the agendav session
        $_SESSION['agendav_sessid'] = $guid;
    }

    function logout($args)
    {
        $rcmail = rcmail::get_instance();

        $dbh = new PDO($this->get_db_driver().':dbname='.$rcmail->config->get('agendav_dbname', false).';host='.$rcmail->config->get('agendav_dbhost', false), $rcmail->config->get('agendav_dbuser', false), $rcmail->config->get('agendav_dbpass', false));
        $stmt = $dbh->prepare("delete from sessions where session_id=:id");
        $stmt->bindParam(':id', $_SESSION['agendav_sessid']);
        $stmt->execute();
        setcookie('agendav_sessid', '', time() - 3600);
    }

    function startup($args)
    {
        $rcmail = rcmail::get_instance();

        // add taskbar button
        $this->add_button(array(
            'command'    => 'agendav',
            'class'      => 'button-agendav',
            'classsel'   => 'button-agendav button-selected',
            'innerclass' => 'button-inner',
            'label'      => 'agendav.agendav',
        ), 'taskbar');

        // add style for taskbar button (must be here) and AgenDAV UI
        $skin_path = $this->local_skin_path();
        if (is_file($this->home . "/$skin_path/agendav.css")) {
            $this->include_stylesheet("$skin_path/agendav.css");
        }
    }

    function action()
    {
        $rcmail = rcmail::get_instance();

        // register UI objects
        $rcmail->output->add_handlers(array(
            'agendavcontent' => array($this, 'content'),
            'tablink' => array($this, 'tablink'),
        ));

        if ($rcmail->action == 'prefs')
            $rcmail->output->set_pagetitle($this->gettext('agendav').' :: '.$this->gettext('prefs'));
        else
            $rcmail->output->set_pagetitle($this->gettext('agendav'));

        $rcmail->output->send('agendav.agendav');
    }

    function tablink($attrib)
    {
        $rcmail = rcmail::get_instance();
        $attrib['name'] = 'agendavlink' . $attrib['action'];
        $attrib['href'] = $rcmail->url(array('_action' => $attrib['action'], '_extwin' => !empty($_REQUEST['_extwin']) ? 1 : null));
        return $rcmail->output->button($attrib);
    }

    function content($attrib)
    {
        $rcmail = rcmail::get_instance();

        switch ($rcmail->action) {
            case 'prefs':
		$src = $this->api->url.'agendav/'.$rcmail->config->get('agendav_path', false).'/web/public/index.php/prefs';
                break;
            default:
		$src = $this->api->url.'agendav/'.$rcmail->config->get('agendav_path', false).'/web/public/index.php/main';
                break;
        }

        $attrib['src'] = $this->resolve_language($src);

        if (empty($attrib['id']))
            $attrib['id'] = 'rcmailagendavcontent';

        $attrib['name'] = $attrib['id'];

        return $rcmail->output->frame($attrib);
    }


    private function resolve_language($path)
    {
        // resolve language placeholder
        $rcmail = rcmail::get_instance();
        $langmap = $rcmail->config->get('agendav_language_map', array('*' => 'en_US'));
        $lang = !empty($langmap[$_SESSION['language']]) ? $langmap[$_SESSION['language']] : $langmap['*'];
        return str_replace('%l', $lang, $path);
    }
}
