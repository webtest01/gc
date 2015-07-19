<?php

class GamersController extends Zend_Controller_Action
{
	public $auth;
	
	public function init()
    {	
		//url helper redirector
		$this->_redirector = $this->_helper->getHelper('Redirector');
		//$this->db = $this->getInvokeArg('bootstrap')->getResource('db');
		$this->db = Zend_Db_Table_Abstract::getDefaultAdapter(); 
		$this->config = Zend_Registry::get('config');
		$this->view->errors = array();
		
		//is login?
		$this->auth = Zend_Auth::getInstance();
		$this->loggedId = isset($this->auth->getIdentity()->id) 
		? $this->auth->getIdentity()->id : NULL;
		$this->loggedHandle = isset($this->auth->getIdentity()->handle) 
		? $this->auth->getIdentity()->handle : NULL;
		$this->loggedEmail = isset($this->auth->getIdentity()->email)
		? $this->auth->getIdentity()->email : NULL;

		
    }
	
	public function preDispatch()
	{
		//parent::preDispatch();
		//$this->_helper->layout->disableLayout();
		//$this->_helper->ViewRenderer->setNoRender();
		$this->_currAction = $this->getRequest()->getActionName();
		
		//Google map
		include 'third-party/GoogleMapAPI.class.php';
		$this->view->map = new GoogleMapAPI('map');
		$this->view->map->setAPIKey($this->config->google->map_key);
	}
	
	public function indexAction()
	{
	
		echo "hi";
	
	}
	
	public function registerAction()
	{
		//Check to see if user is already login
		if($this->loggedEmail){
			$this->_redirect('/');
			return;
		}
		
		//get referrer
		$ns = new Zend_Session_Namespace('referrer');
		$this->view->referby = $ns->referrer;
			
		if($this->getRequest()->isPost()){
			//Validation
			// Valid email address?
			if (! Zend_Validate::is($this->_request->getPost('email'), 'EmailAddress')
				&& $this->_request->getPost('email') != 'me2@localhost'){
				$this->view->errors[] = "Invalid e-mail address.";
			} 
			//E-mail cannot already exist in the database
			$user = new Default_Model_User();
			$foundUser = $user->getUserByEmail($this->_request->getPost('email'));
			if(isset($foundUser->id)){
				$this->view->errors[] = "Email address already in database.";
			}
			
			//Handle must be between 2-20 characters
			$validator = new Zend_Validate_StringLength(2, 20);
			if(! $validator->isValid($this->_request->getPost('handle'))){
				$this->view->errors[] = "Handle must be between 2 and 14 characters.";
			}
			
			// Handle must consist solely of alphanumeric characters
			$validHandle = new Zend_Validate_Alnum();
			if (! $validHandle->isValid($this->_request->getPost('handle'))) {
				$this->view->errors[] = "Handle must consist of letters and numbers.";
			} // end valid handle
			
			// Handle cannot already exist in database
			$foundUser = $user->getUserByHandle($this->_request->getPost('handle'));
			if (isset($foundUser->id)) {
				$this->view->errors[] = "Handle already exists in database.";
			}
			
			// Password must between 6 to 20 characters
			$validPswd = new Zend_Validate_StringLength(6,20);
			if (! $validPswd->isValid($this->_request->getPost('password'))) {
				$this->view->errors[] = "Password must be at least 6 characters.";
			} // end valid password
			
			// First name must not be empty
			$validFirstName = new Zend_Validate_NotEmpty();
			if (! $validFirstName->isValid($this->_request->getPost('first_name'))) {
				$this->view->errors[] = "Please provide your first name.";
			} // end valid first name
			
			// Last name must not be empty
			$validLastName = new Zend_Validate_NotEmpty();
			if (! $validLastName->isValid($this->_request->getPost('last_name'))) {
				$this->view->errors[] = "Please provide your last name.";
			} // end valid last name
			
			// Valid gender?
			if (! Zend_Validate::is($this->_request->getPost('gender'), 'NotEmpty')) {
				$this->view->errors[] = "Please identify your gender.";
			} // end valid gender
			
			//Address not empty?
			if(! Zend_Validate::is($this->_request->getPost('address'), 'NotEmpty')){
				$this->view->errors[] = "Please enter your address.";
			}
			
				//if errors exist, prepopulate the form
				if(count($this->view->errors) > 0){
				$this->view->email = $this->_request->getPost('email');
			 	$this->view->handle = $this->_request->getPost('handle');
			 	$this->view->first_name = $this->_request->getPost('first_name');
			 	$this->view->last_name = $this->_request->getPost('last_name');
			 	$this->view->gender = $this->_request->getPost('gender');
				$this->view->address = $this->_request->getPost('address');
				}else{ //No errors, add user to the database and send confirmation e-mail
				
				//Generate random keys used for registration confirmation
				$registrationKey = $this->_helper->generator(32, 'alpha');
				
				// Prepare the data array for database insertion
				$data = array (
					'email' => $this->_request->getPost('email'),
					'password' => md5($this->_request->getPost('password')),
					'registration_key' => $registrationKey,
					'handle' => $this->_request->getPost('handle'),
					'first_name' => $this->_request->getPost('first_name'),
					'last_name' => $this->_request->getPost('last_name'),
					'gender' => $this->_request->getPost('gender'),
					'address' => $this->_request->getPost('address'),
					'created_at' => date('Y-m-d H:i:s'),
					'updated_at' => date('Y-m-d H:i:s'),
					'last_login' => date('Y-m-d H:i:s'),
					'referby' => $this->_request->getPost('referrer')
				);
				
				//Create a new mail object
				 try {
					 $mail = new Zend_Mail();
					
					 // Set the From, To, and Subject headers
					 $mail->setFrom($this->config->email->from_admin);
					 $mail->addTo($this->_request->getPost('email'),
					 "{$this->_request->getPost('first_name')}
					 {$this->_request->getPost('last_name')}");
					 $mail->setSubject('Your game account has been created');
					
					 // Retrieve the e-mail template
					 include "emailTemplates/_email-confirm-registration.phtml";
					
					 // Attach the e-mail template to the e-mail and send it
					 $mail->setBodyText($email);
					 $mail->send();
					
					 $this->view->success = 1;
					 } catch (Exception $e) {
						 $this->view->errors[] = "We were unable to send your confirmation 		
						 e-mail.
					Please contact {$this->config->email->support}.";
				 }
				 
				 //If succcessful at sending mail, insert into database
				 if($this->view->success == 1){
					// Insert the registration data into the database
					$user = new Default_Model_User();
					$user->insert($data);
				 }
				
			
				} //end else (w/ no errors)
		} //end if isPost()
	}
	
	//Completes registration process by validating email address
	public function verifyAction()
	{
		$this->view->headTitle("Registration Process");
		
		//Retrieve key from url
		$registrationKey = $this->getRequest()->getParam('key');
		
		//Identitfy the user associated with the key
		$user = new Default_Model_User();
		
		//Determine is user already confirm
		if($user->isUserConfirmed($registrationKey)){
		$this->view->isConfirmed = 1;
		$this->view->errors[] = "User is already confirmed";
		return;
		}

		$resultRow = $user->getUserByRegkey($registrationKey);
		
		//If the user has been located, set the confirmed column.
		if(count($resultRow)){
			$resultRow->confirmed = 1;
			$resultRow->save();
			
			$this->view->success = 1;
			$this->view->firstName = $resultRow->first_name;
		
		} else{
			$this->view->errors[] = "Unable to locate registration key";
		}

	}
	
	public function loginAction()
	{
		$this->view->headTitle("game Login");
			
		//Check to see if user is already login
		if($this->loggedEmail){
			$this->_redirect('/');
			return;
		}
		
		if($this->getRequest()->isPost()){
		
			//Learn/Use Zend_Form instead
			//$fp = new My_FormProcessor();
			//$fp->process($this->getRequest());
			
			//Retrieve email and password
			$emailhandle = $this->_request->getPost('emailhandle');
			$password = $this->_request->getPost('password');
			
			// Make sure the email/handle and password were provided
		    if (empty($emailhandle) || empty($password)) {
		 		$this->view->errors[] = "Provide e-mail address or handle and password.";
		 	} else{
			
			//determine whether it was an email or handle
			$identity  = (preg_match("/@/", $emailhandle)) ? 'email' : 'handle';

			// Identify the authentication adapter
			$authAdapter = new Zend_Auth_Adapter_DbTable($this->db);
			$authAdapter->setTableName('users')
						->setIdentityColumn($identity)
						->setCredentialColumn('password')
						->setCredentialTreatment('MD5(?)');
						
			//Pass provided information to adapter
			$authAdapter->setIdentity($emailhandle);
			$authAdapter->setCredential($password);
			
			//Authenticate!
			$auth = Zend_Auth::getInstance();
			$result = $auth->authenticate($authAdapter);
			
				//Did the participant successfully login?
				if($result->isValid()){

					//Retrieve user to update login timestamp
					$user = new Default_Model_User();
					
					$updateLogin  = ($identity == 'email') ? 
					$user->getUserByEmail($emailhandle) : 
					$user->getUserByHandle($emailhandle);
					
					if($updateLogin->confirmed == 1){
					// create identity data and write it to session
					//$identity = self::_createAuthIdentity($updateLogin);

					//$storage = new Zend_Auth_Storage_Session();
                    //$storage->write($authAdapter->getResultRowObject());
					$auth->getStorage()->write($authAdapter->getResultRowObject());
					
						//Update login
						$updateLogin->last_login = date('Y-m-d H:i:s');
						$updateLogin->save();
						
						//Redirect user to index page
						$this->_redirect('/gamers/updateprofile');
						//$this->_helper->debug($authAdapter->getResultRowObject());
					} else{
						$this->view->errors[] = "Email address not confirmed";
					}
				} else{
					$this->view->valid = 0;
					$this->view->errors[] = "Login failed.";
				}
				
				
			} //end else (email and password provided)

		} //end if isPost()
	}
	
	public function logoutAction()
	{
		Zend_Auth::getInstance()->clearIdentity();
		$this->_redirect('/');
		return;
	
	}
	
	public function forgotAction()
	{
		$this->view->headTitle("Forgot your password?");
		
		if($this->getRequest()->isPost()){
		
			//Validate email
			$email = $this->_request->getPost('email');
			if(!Zend_Validate::is($email, 'EmailAddress') && $email != 'me2@localhost'){
				$this->view->errors[] = "Please provide a valid email address";
			} else{
			
					$user = new Default_Model_User();
					$foundUser = $user->getUserByEmail($email);
					
					//If the user has been found, generate a key and mail it to user
					if(count($foundUser) == 1){
						$registrationKey = $this->_helper->generator(32, 'alpha');
						$foundUser->registration_key = $registrationKey;
						$foundUser->save();
						
						
						try{
							//Create a new mail object
							$mail = new Zend_Mail();
							$mail->setFrom($this->config->email->from_admin);
							$mail->addTo($this->_request->getPost('email'),
							 "{$foundUser->first_name}
							 {$foundUser->last_name}");
							$mail->setSubject('Reset your password');
							
							include "emailTemplates/_email-forgot-password.html";
							
							$mail->setBodyText($email);
							$mail->send();
							
						} catch(Exception $e){
						
						$this->view->errors[] = "There was a problem sending the e-mail.";
						
						}
				
					 } else{
					 	$this->view->errors[] = "Email not in database";
					 }
					
					if(count($this->view->errors) == 0){
						$this->view->mailsent = 1;
					}
				} //end else valid email
		
		} //end isPost()
	}
	
	//Completes password recovery process
	public function resetAction()
	{
		$this->view->headTitle("Reset your password");
	
		//If form is submitted, reset the password
		if($this->getRequest()->isPost()){
		
			//Validation
			//Password must be between 6-20 characters
			$valid_pswd = new Zend_Validate_StringLength(6, 20);
			if(! $valid_pswd->isValid($this->_request->getPost('password'))){
				$this->view->errors[] = "Password must be at least 6 characters.";
			}
			
			//Password must match
			if($this->_request->getPost('password') != 
			   $this->_request->getPost('password2')){
				$this->view->errors[] = "Your passwords do not match.";
			}
			
			//No errors, so update the password
			if(count($this->view->errors) == 0){
				
				//Find user row to update via registration_key column
				$user = new Default_Model_User();
				$resultRow = $user->getUserByRegkey($this->_request->getPost('key'));
				
				if(count($resultRow) == 1){
					$resultRow->password = md5($this->_request->getPost('password'));
					$resultRow->save();
					$this->view->updated = 1;
				}
				
			} else{ //Errors, so pass key back to form
				$this->view->success = 1;
				$this->view->key = $this->_request->getPost('key');
			}
			
			
		}else{
			// User has clicked the emailed password recovery link. Find the user
			// using the recovery key, and prepare the password reset form
			
			//Retrieve key from url
			$recoveryKey = $this->getRequest()->getParam('key');
			
			$user = new Default_Model_User();
			$resultRow = $user->getUserByRegkey($recoveryKey);
			
				if(count($resultRow)){
					$resultRow->save();
					$this->view->success = 1;
					$this->view->key = $recoveryKey;
				} else{
					$this->view->errors[] = "Unable to locate password recovery key.";
				}
		
		} //end else
	}
	
	public function profileAction()
	{
	
		$handle = $this->_request->getParam('handle');	
			
		$this->view->headTitle("Gamer Profile: {$handle}");
		
		$user = new Default_Model_User();
		$this->view->gamer = $user->getUserByHandle($handle);
		
		if(!isset($this->view->gamer->id)){
			$this->view->errors = "This user does not exist.";
			return;
		}
		
		//Determine gender for outputting phrase
		$gender = ($this->view->gamer->gender == 'm') ? 'his' : 'her';
		
		//Google MAP
		$this->view->map->setHeight(300); $this->view->map->setWidth(300);
		$this->view->map->disableMapControls();
		$coords = $this->view->map->getGeocode($this->view->gamer->address);
		$this->view->map->setCenterCoords($coords['lon'], $coords['lat']);
		$this->view->map->addMarkerByAddress($this->view->gamer->address, 
		"This is {$gender} place!");
		$this->view->map->disableDirections();
		$this->view->map->setZoomLevel(14);
		
		//Get list of friends based on user handle
		$this->view->friends = $this->view->gamer->getFriends();
		
		//Display invitation if user is logged
		$this->view->loggedEmail = $this->loggedEmail;
		//Insert user_id of logged user that's going to comment on profile
		$this->view->loggedId = $this->loggedId;
		//Insert handle of logged user for removing comment
		$this->view->loggedHandle = $this->loggedHandle;
			
		//get current page
		$currpage = $this->getRequest()->getQuery('page');	
		$paginationCount = 3;
		//Get list of comments
		$comment = new Default_Model_Comment();
		$this->view->comments = $comment->getUserComments($this->view->gamer->id, 		
		$paginationCount, $currpage);
		
		$session = new Zend_Session_Namespace('captcha');
		if(isset($session->phrase)){
			$phrase = $session->phrase;
		}
		
		//generate captcha
		$captcha = new Zend_Captcha_Image(array('wordLen'=>5));
		$captcha->setFont("game\library\data\VeraBd.ttf");
		$captcha->setImgDir("game\public\images");
		$captcha->setImgUrl($this->view->siteWideProperty . "/images/");
		$captcha->generate();
		$session->phrase = $captcha->getWord();
		$this->view->captcha  = $captcha->render($this->view);
		
		if($this->getRequest()->getQuery('captchaerr')){
			$this->view->captchaerr = 1;
			$this->view->errors[] = "Invalid captcha";
		}
		
	}
	
	public function inviteAction()
	{
		
		//get handle of the logged person
		$user = new Default_Model_User();
		$resultRow = $user->getUserByEmail($this->loggedEmail);
		
		$loggedHandle = $resultRow->handle;
		$loggedId = $resultRow->id;
		
		$handle = $this->_request->getParam('handle');
		$resultRow = $user->getUserByHandle($handle);
		$handleId = $resultRow->id;

		$invite = new Default_Model_Invitation();
		if($invite->createInvitation($loggedId, $handleId)){
			$this->view->success = 1;
		} else{
			$this->view->success = 0;
		}
	}
	
	public function connectedAction()
	{
	
		// Set the page title
		$this->view->headTitle("Complete a game Connection");
		
		//Retrieve the invitation key
		$key = $this->getRequest()->getParam('key');
		
		// Retrieve the invitation
		$invitation = new Default_Model_Invitation();
		//$this->view->outstandingInvitation = $invitation->getInvitation($key);
		
		 // Complete the invitation process
		 $connected = $invitation->completeInvitation($key);
		
		 // Determine the outcome response
		 if ($connected) {
		 	$this->view->success = 1;
		 } else {
			 $this->view->errors[] = "Could not complete the connection request.";
		 }

	}
	
	public function updateprofileAction()
	{
		// Set the page title
		$this->view->headTitle("Update Your Profile");
		
		//if not logged in, user can't edit profile
		if(!$this->loggedEmail){
			$this->_redirect('/'); 
			return;
		}
		
		$user = new Default_Model_User();
		$resultRow = $user->getUserByEmail($this->loggedEmail);
		
		if($this->getRequest()->isPost()){
			
			$resultRow->email = $this->getRequest()->getPost('email');
			$resultRow->first_name = $this->getRequest()->getPost('first_name');
			$resultRow->last_name = $this->getRequest()->getPost('last_name');
			$resultRow->gender = $this->getRequest()->getPost('gender');
			$resultRow->address = $this->getRequest()->getPost('address');
			
			if(strlen($this->getRequest()->getPost('password'))){
				$resultRow->password = $this->getRequest()->getPost('password');
			}
			$resultRow->updated_at = date('Y-m-d H:i:s');
			$resultRow->save();
			
		} 
			
		$this->view->email = $resultRow->email;
		$this->view->first_name = $resultRow->first_name;
		$this->view->last_name = $resultRow->last_name;
		$this->view->gender = $resultRow->gender;
		$this->view->address = $resultRow->address;
		$this->view->handle = $resultRow->handle;
	
	}


	public function commentAction() //perhaps add captcha? and paginatinator?
	{
		$this->_helper->layout->disableLayout();
		$this->_helper->ViewRenderer->setNoRender();
		
		$commentDb = new Default_Model_Comment();
		
		/*
		$removeId = $this->getRequest()->getQuery('remove');
		
		//if a comment is to be removed
		if(isset($removeId)){
			//get handle of profile page
			$profile_id = $commentDb->find($removeId)->current()->profile_id;
			$user = new Default_Model_User();
			$handle = $user->find($profile_id)->current()->handle;
			
			//delete the comment
			$where = $commentDb->getAdapter()->quoteInto('id = ?', $removeId);
			$commentDb->delete($where);
		}*/
		
		$session = new Zend_Session_Namespace('captcha');
		if(isset($session->phrase)){
			$phrase = $session->phrase;
		}
		
		if($this->getRequest()->isPost()){
			$handle = $this->getRequest()->getPost('handle');
			$profile_id = $this->getRequest()->getPost('profile_id');
			$user_id = $this->getRequest()->getPost('user_id');
			$comment = $this->getRequest()->getPost('comment');
			$captchatext = $this->getRequest()->getPost('captchatext');
			
			// Valid captcha?
			$isValidCaptcha = ($captchatext == $phrase) ? true : false;

			//process incoming data (if comment not empty and valid captcha)
			if(Zend_Validate::is($comment, 'NotEmpty') && $isValidCaptcha){
			
				$data['user_id'] = $user_id;
				$data['profile_id'] = $profile_id;
				$data['comment'] = $comment;
				$data['posted_at'] = date('Y-m-d H:i:s');
				$commentDb->insert($data);
								
			}
		}
	
		//redirect back to profile
		$handle = strtolower($handle);
		if($isValidCaptcha)
			$this->_redirector->gotoUrl("/gamers/profile/{$handle}"); 
		else
			$this->_redirector->gotoUrl("/gamers/profile/{$handle}/?captchaerr=1"); 
			
	}

	//private method to hold object for auth session
	//equalivalent of $_SESSION['loggedId'] = $id, $_SESSION['loggedHandle'] = $handle, etc
	private static function _createAuthIdentity($user)
	{
		$identity = new stdClass;
		$identity->id = $user->id;
		$identity->handle = $user->handle;
		//$identity->user_type = $user->user_type;
		$identity->first_name = $user->first_name;
		$identity->last_name = $user->last_name;
		$identity->email = $user->email;
		return $identity;
	}
	
}