<?php 
defined('BASEPATH') or exit('No direct script access allowed');

class Weixin_dev extends MY_Controller{
    
    private $AppID; //应用ID
    private $AppSecret; //应用密匙
    
    public function __construct(){
        parent::__construct();
        $this->AppID = C('appid_secret.xitai.app_id');
        $this->AppSecret = C('appid_secret.xitai.app_secret');
    }
    
    /**
     * 1 setup 非静默授权
     * 获取code
     */
    public function login(){
        $data =$this->data;
        $redirect_url = 'https://open.weixin.qq.com/connect/oauth2/authorize?AppID='.$this->AppID;
        $redirect_url .= '&redirect_uri='.urlencode($this->data['domain']['www']['url'].'/weixin_dev/get_access_token');
        $redirect_url .= "&response_type=code&scope=snsapi_userinfo&state=123#wechat_redirect";
	    header('location:' . $redirect_url);
        exit;
    }
    
    /**
     * 2 setup 非静默授权
     * 通过code换取网页授权access_token 获取openid
     */
    public function get_access_token(){
        $code = $this->input->get('code');
        if(empty($code)){
            $this->return_failed('获取信息失败！');
        }
        $openid_url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={$this->AppID}&secret={$this->AppSecret}&code={$code}&grant_type=authorization_code";
        $openid_ch = curl_init();
        curl_setopt($openid_ch, CURLOPT_URL,$openid_url);
        curl_setopt($openid_ch, CURLOPT_RETURNTRANSFER,1);
        curl_setopt($openid_ch, CURLOPT_SSL_VERIFYPEER,0);
        $openid_data = curl_exec($openid_ch);
        curl_close($openid_ch);
        $openid_arr = json_decode($openid_data, true);
        //如果拉取不到用户openid信息
        if(!isset($openid_arr['openid'])){
            $this->return_failed('获取信息失败！');
        }
        $openid = $openid_arr['openid'];
        $access_token = $openid_arr['access_token'];
        $refresh_token = $openid_arr['refresh_token'];
        //判断access_token是否过期
        $check_access_token_url = "https://api.weixin.qq.com/sns/auth?access_token={$access_token}&openid={$openid} ";
        $check_data = json_decode($this->httpGet($check_access_token_url), true);
        if(isset($check_data['errcode']) && $check_data['errcode'] == 0){
            //没有过期
            $res = array(
                'openid' => $openid,
                'access_token' => $access_token
            );
        }else{
            $refresh = $this->refresh_token($refresh_token);
            $res = array(
                'openid' => $refresh['openid'],
                'access_token' => $refresh['access_token']
            );
        }
        $user_info = $this->get_weixin_user_info($res);
        $this->add_user_and_login($user_info);
    }
    
    /**
     * 刷新access_token
     * @param unknown $refresh_token
     */
    private function refresh_token($refresh_token){
        $url = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid={$this->AppID}&grant_type=refresh_token&refresh_token={$refresh_token}";
        $refresh_data = json_decode($this->httpGet($url), true);
        return $refresh_data;
    }
    
    /**
     * 3 setup 非静默授权
     * 获取用户信息
     * @param [openid access_token] $res
     * @return mixed
     */
    private function get_weixin_user_info($res){
        if(!$res){
            $this->return_failed('获取授权信息失败！');
        }
        $url = 'https://api.weixin.qq.com/sns/userinfo?access_token='.$res['access_token'].'&openid='.$res['openid'].'&lang=zh_CN';
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,0);
        $data = curl_exec($ch);
        curl_close($ch);
        return json_decode($data, true);
    }
    
    /**
     * 添加用户到数据库并登陆
     * @param unknown $user_info
     */
    private function add_user_and_login($user_info){
        if(!empty($user_info) || !isset($user_info['openid'])){
            //查找open_id 是否绑定本平台账户，若绑定则使用平台账户登录
            $user = $this->Muser->get_one('*', array('open_id' => $user_info['openid'], 'is_del' => 0));
            if($user){
                unset($user['password']);
                setcookie("user", encrypt($user_info), time() + C('site_config.cookie_expire'), '/', C('site_config.root_domain'));
                //跳转到登录前的页面或个人中心
                $url = $data['domain']['base']['url'];
                $return_url = $this->input->cookie('return_url');
                if(isset($return_url) && !empty($return_url))
                {
                    $url = $return_url;
                }
                redirect($url);
            }else{
                $add['open_id'] = $user_info['openid'];
                $add['nickname'] = $user_info['nickname'];
                $add['sex'] = $user_info['sex'];
                $add['head_img'] = $user_info['headimgurl'];
                $add['address'] = $user_info['country'].$user_info['province'].$user_info['city'];
                $add['create_time'] = $add['update_time'] = date('Y-m-d H:i:s');
                $res = $this->Muser->create($add);
                if(!$res){
                    $this->return_failed('注册失败！');
                }
                $add['id'] = $res;
                setcookie("user", encrypt($add), time() + C('site_config.cookie_expire'), '/', C('site_config.root_domain'));
                redirect($data['domain']['base']['url']);
            }
        }else{
            $this->return_failed('获取信息失败，请重试！');
        }   
    }
    /*=============================================================================================*/
    private function getconfig(){
        return $this->getSignPackage();
    }
    
    public function share(){
        $data = $this->data;
        //获取微信config接口注入权限验证配置
        $data['config'] = $this->getconfig();
        $this->load->view('weixin/share', $data);
    }
    
    public function download(){
        $media_id = trim($this->input->get('media_id'));
        if(empty($media_id)){
            exit();
        }
        $url = "http://file.api.weixin.qq.com/cgi-bin/media/get?access_token=".$this->getAccessToken()."&media_id={$media_id}";
        //获取微信“获取临时素材”接口返回来的内容（即刚上传的图片）  
        $handle = file_get_contents($url);
        //以读写方式打开一个文件，若没有，则自动创建  
        $resource = fopen("../../uploads/image/{$media_id}.jpg" , 'w+');
        //将图片内容写入上述新建的文件  
        fwrite($resource, $handle);
        //关闭资源  
        fclose($resource);
        echo '完成上传图片';
    }

    public function getSignPackage() {
        $jsapiTicket = $this->getJsApiTicket();
    
        // 注意 URL 一定要动态获取，不能 hardcode.
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    
        $timestamp = time();
        $nonceStr = $this->createNonceStr();
    
        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";
    
        $signature = sha1($string);
    
        $signPackage = array(
            "AppID"     => $this->AppID,
            "nonceStr"  => $nonceStr,
            "timestamp" => $timestamp,
            "url"       => $url,
            "signature" => $signature,
            "rawString" => $string
        );
        return $signPackage;
    }
    
    private function createNonceStr($length = 16) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }
    
private function getJsApiTicket() {
    // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
    $data = (array) json_decode($this->get_php_file("jsapi_ticket.php"));
    if (!isset($data['expire_time']) || $data['expire_time'] < time()) {
      $accessToken = $this->getAccessToken();
      // 如果是企业号用以下 URL 获取 ticket
      // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
      $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=$accessToken";
      $res = json_decode($this->httpGet($url));
      $ticket = $res->ticket;
      if ($ticket) {
        $data['expire_time'] = time() + 7000;
        $data['jsapi_ticket'] = $ticket;
        $this->set_php_file("jsapi_ticket.php", json_encode($data));
      }
    } else {
      $ticket = $data['jsapi_ticket'];
    }

    return $ticket;
  }

  private function getAccessToken() {
    // access_token 应该全局存储与更新，以下代码以写入到文件中做示例
    $data = (array) json_decode($this->get_php_file("access_token.php"));
    if (!isset($data['expire_time']) || $data['expire_time'] < time()) {
      // 如果是企业号用以下URL获取access_token
      // $url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=$this->appId&corpsecret=$this->appSecret";
      $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$this->AppID&secret=$this->AppSecret";
      $res = json_decode($this->httpGet($url));
      $access_token = $res->access_token;
      if ($access_token) {
        $data['expire_time'] = time() + 7000;
        $data['access_token'] = $access_token;
        $this->set_php_file("access_token.php", json_encode($data));
      }
    } else {
      $access_token = $data['access_token'];
    }
    return $access_token;
  }
    
    private function httpGet($url) {
        $curl = curl_init();
        @curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        @curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        // 为保证第三方服务器与微信服务器之间数据传输的安全性，所有微信接口采用https方式调用，必须使用下面2行代码打开ssl安全校验。
        // 如果在部署过程中代码在此处验证失败，请到 http://curl.haxx.se/ca/cacert.pem 下载新的证书判别文件。
        @curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        @curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, true);
        @curl_setopt($curl, CURLOPT_URL, $url);
    
        $res = curl_exec($curl);
        curl_close($curl);
    
        return $res;
    }
    
    private function get_php_file($filename) {
        if(file_exists('./cache/'.$filename)){
            return trim(substr(file_get_contents('./cache/'.$filename), 15));
        }else{
            return null;
        }
        
    }
    
    private function set_php_file($filename, $content) {
        $fp = fopen('./cache/'.$filename, "w");
        fwrite($fp, "<?php exit();?>" . $content);
        fclose($fp);
    }
}
