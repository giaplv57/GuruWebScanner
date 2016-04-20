<?php
/**
 * AreteX_WPI_DI_Authorization
 * 
 * @package AreteX For WordPress
 * @author 3B Alliance, LLC
 * @copyright 2013
 * @access public
 * 
 * AreteX WordPress Interface - Delivery Interface Abstaract
 * 
 */
 
 if ( ! class_exists( 'AreteX_WPI_DI' ) ) {
    require_once(plugin_dir_path( __FILE__ ).'AreteX_WPI.class.php');    
    require_once(plugin_dir_path( __FILE__ ).'AreteXClientEngine/Delivery.class.php');

        
    abstract class  AreteX_WPI_DI extends AreteX_WPI {
        
        public static function get_types($id=null) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/types';
            if ($id)
            {
                 return null; // Not currently implemented. 
                 $url .= '/'.$id;                 
            }
               
            
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,array(),$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);
                
            }
            
            return $response;
        }
        
        public static function get_delivery_code($id=null,$exact=false) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/manifests';
            if ($id)
            {                
                 $url .= '/'.$id;                 
            }
            
           
             if ($exact)
                $data = array('exact'=>'true');
            else
                $data = array();   
            
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,$data,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);
                
            }
            
            return $response;
            
        }
        
        public static function get_products_by_deliverable($deliverable_id) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/deliverables/$deliverable_id/products";
            
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,$data,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);
                
            }
            
            return $response;
            
        }

        
        public static function get_deliverables_by_type($type,$descriptor) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/deliverables/type/$type/descriptor/$descriptor";
            
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);
                
            }
            
            return $response;
            
        }
        
        public static function get_deliverables_by_id($id) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/deliverables/$id?exact=true";
            
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);
                
            }
            
            return $response;
            
        }
        
        public static function get_deliverable_payouts($id) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/deliverables/$id/payouts";
            
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response);
                
            }
            
            return $response;
            
        }
        
        public static function save_deliverable_payouts($id,$payouts) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/deliverables/$id/payouts";
            
          //  error_log($url);
            
            $data['data'] = json_encode($payouts);
                         
            $creds = self::makeLoginCreds('master');
            
          //  error_log("Creds:".var_export($creds,true));
                                  
            extract($creds);
          
            $response = self::rest_post($url,$data,$username,$password);

            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response);
                
            }
            
            return $response;
            
        }
        
        public static function update_authorization($id,$new_authorization,$new_end_date) {
            
            $url = get_option('aretex_bas_endpoint');
            $url .= "/api/delivery/authorizations/$id";
            
            
            $data['expiration_date'] = $new_end_date;
            $data['authorization_status'] = $new_authorization;
                         
            $creds = self::makeLoginCreds('master');
            
          //  error_log("Creds:".var_export($creds,true));
                                  
            extract($creds);
          
            $response = self::rest_post($url,$data,$username,$password);          

            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response);
                
            }
            
            return $response;
            
            
        }
        
        public static function get_authorization_by_key($descriptor,$key) {
            
            $key = urlencode($key);
            $url = get_option('aretex_bas_endpoint');
            $url .= "/api/delivery/authorizations/descriptor/$descriptor/access_key/$key";
            
        //    error_log($url);
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
          //  error_log("URI: $url\nResults: ".var_export($response,true));
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                 
                 
                $response = json_decode($response,true);                
                
            }
                       
            
            return $response;
            
        }
        
        public static function get_manifests() {
                       
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $url .= "/manifests"; 
           
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);                
                
            }
            
            return $response;
            
        }
        
        public static function get_manifest_by_code($delivery_code) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= "/delivery/manifests/$delivery_code";
            
           
                         
            $creds = self::makeLoginCreds();                      
            extract($creds);
          
            $response = self::rest_get($url,null,$username,$password);
            if ($response['response']['code'] == 200) {
                $response = $response['body'];
                
                $response = json_decode($response,true);                
                
            }
            
            return $response;
            
        }
        
        public static function delete_manifest($delivery_code) {
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/manifests/'.$delivery_code;
            
            
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            

             $results = self::rest_delete($url,array(),$username,$password);
           //  error_log(var_export($results,true));
           
                        
            if ($results['response']['code'] == 200 || $results['response']['code'] == 201) {
                $response = $results['body'];
                $response = json_decode($response);
                               
                // error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
              //   error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
        
        }
        
        public static function save_manifest($manifest_id,$manifest_content,$create_only=true,$add_to_product=false) {
            $manifest = new ManifestByReference();
            foreach ($manifest_id as $key => $value)
            {
                $manifest->$key = $value;
            }
            $manifest->deliverable_ids = $manifest_content;
            
          //  error_log("save_manifest(".var_export($manifest_id,true).var_export($manifest_content,true).var_export($create_only,true).var_export($add_to_product,true).")...END SAVE MANIFEST\n");           
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/manifests';
            if (! $create_only) {
                $url .= '/'.$manifest->delivery_code;
            }
            $data['data'] = json_encode($manifest);
            $data['create_only'] = $create_only;
            $data['full_deliverables'] = false;
            
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
             $results = self::rest_post($url,$data,$username,$password);
           //  error_log(var_export($results,true));
                    
           
                        
            if ($results['response']['code'] == 200 || $results['response']['code'] == 201) {
                $response = $results['body'];
                
                $saved_manifest = json_decode($response);
                if ($create_only)
                    $manifest_code = $saved_manifest->delivery_code;
                else
                    $manifest_code = $manifest->delivery_code;
                
                if ($add_to_product) {
                    $url = get_option('aretex_cat_endpoint');
                    $url .= '/products/'.$add_to_product.'/delivery_code/'.$manifest_code;
                  //  error_log($url);
                    $data = array();
                    $results = self::rest_post($url,$data,$username,$password);
                    error_log("Results = ".var_export($results,true));
                }
                
                $response = json_decode($response);
                               
                // error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
              //   error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
            
        }
        
        public static function jsDeliverableSearch($dom_id) {
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/deliverables';
            $license_key = get_option('aretex_license_key');
            $app_key = get_option('aretex_api_key');
            $password = self::getEncPw();
            // $private_key = get_option('aretex_private_key');
            $crypton = new Crypton();
            $keys = $crypton->get_keys('aretex_wp',$password);
            $private_key = $keys['privatekey'];
            $creds = AreteX_API::Ajax_credentials($license_key,$app_key,$private_key);            
            extract($creds);
            
            $js = "\n set_deliverable_search('$dom_id','$url','$username','$password'); \n";
            
            return $js;
            
        }
        
        
        
        public static function delete_deliverable($deliverable_id) {
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/deliverables/'.$deliverable_id;
           
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
            $results = self::rest_delete($url,array(),$username,$password);
            // error_log(var_export($results,true));
           
                        
            if ($results['response']['code'] == 200 || $results['response']['code'] == 201) {
                $response = $results['body'];
                $response = json_decode($response);
                               
              //   error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
                // error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
            
            
        }
        
        
        public static function create_deliverable(Deliverable $deliverable) {
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/deliverables';
            $data['data'] = json_encode($deliverable);
            $data['create_only'] = true;
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
             $results = self::rest_post($url,$data,$username,$password);
    //         error_log(var_export($results,true));
           
                        
            if ($results['response']['code'] == 200 || $results['response']['code'] == 201) {
                $response = $results['body'];
                $response = json_decode($response);
                               
  //               error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
//                 error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
            
            
        }
        
         public static function save_deliverable(Deliverable $deliverable) {
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery/deliverables/'.$deliverable->deliverable_code;
            $data['data'] = json_encode($deliverable);
            $data['create_only'] = false;
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
             $results = self::rest_post($url,$data,$username,$password);
            
           
                        
            if ($results['response']['code'] == 200 || $results['response']['code'] == 201) {
                $response = $results['body'];
                $response = json_decode($response);
                                                         
              
                return $response;                 
            }
            else {
                 
          //       error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
            
            
        }
        
        public static function create_delivery(DeliveryManifest $delivery){
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            $data['data'] = json_encode($tracking);
            $data['create_only'] = true;
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
            
            $results = self::rest_post($url,$data,$username,$password);
        //     error_log(var_export($results,true));
           
                        
            if ($results['response']['code'] == 200) {
                $response = $results['body'];
                $response = json_decode($response);
                               
              //   error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
               //  error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
                
            
        }
        
        public static function update_delivery(DeliveryManifest $delivery,$create_only = true){
            
            $url = get_option('aretex_cat_endpoint');
            $url .= '/delivery';
            if ($delivery->id > 0)
                $url .= '/'.$delivery->id;
            else
                $url .= '/'.$deliery->delivery_code;
                
            $data['data'] = json_encode($tracking);
            $data['create_only'] = $create_only;
            $creds = self::makeLoginCreds('master');                      
            extract($creds);
            
            
            $results = self::rest_post($url,$data,$username,$password);
           //  error_log(var_export($results,true));
           
                        
            if ($results['response']['code'] == 200) {
                $response = $results['body'];
                $response = json_decode($response);
                               
              //   error_log("Returning: ".var_export($response,true));              
              
                return $response;                 
            }
            else {
                 
                // error_log("Returning: Error:".var_export($results['body'],true));  
                return 'Error: '.$results['body'];
            }
            
                
            
        }
        
    }
 }
?>