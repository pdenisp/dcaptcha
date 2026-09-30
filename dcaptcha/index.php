<?php

class DcaptchaPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'dCaptcha',
		AUTHOR   = 'denisp',
		URL      = 'https://kostroma.net/',
		VERSION  = '1.0',
		RELEASE  = '2029-09-30',
		REQUIRED = '2.35.3',
		CATEGORY = 'General',
		LICENSE  = 'MIT',
		DESCRIPTION = 'dCaptcha';

	/**
	 * @return void
	 */
	public function Init() : void
	{
		$this->UseLangs(true);

		$this->addJs('js/dcaptcha.js');

		$this->addHook('json.before-login', 'BeforeLogin');
		$this->addHook('json.after-login', 'AfterLogin');
		$this->addHook('main.content-security-policy', 'ContentSecurityPolicy');
	}

	protected function configMapping() : array
	{
		return array(
			\RainLoop\Plugins\Property::NewInstance('public_key')->SetLabel('Site key')
				->SetAllowedInJs(true)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('private_key')->SetLabel('Secret key')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('error_limit')->SetLabel('Limit')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::SELECTION)
				->SetDefaultValue(array('0', 1, 2, 3, 4, 5))
				->SetDescription('')
		);
	}

	/**
	 * @return string
	 */
	private function getCaptchaCacherKey()
	{
		return 'CaptchaNew/Login/'.\RainLoop\Utils::GetConnectionToken();
	}

	/**
	 * @return int
	 */
	private function getLimit()
	{
		$iConfigLimit = $this->Config()->Get('plugin', 'error_limit', 0);
		if (0 < $iConfigLimit) {
			$oCacher = $this->Manager()->Actions()->Cacher();
			$sLimit = $oCacher && $oCacher->IsInited() ? $oCacher->Get($this->getCaptchaCacherKey()) : '0';

			if (\is_numeric($sLimit)) {
				$iConfigLimit -= (int) $sLimit;
			}
		}

		return $iConfigLimit;
	}

	/**
	 * @return void
	 */
	public function FilterAppDataPluginSection(bool $bAdmin, bool $bAuth, array &$aConfig) : void
	{
		if (!$bAdmin && !$bAuth) {
			$aConfig['show_captcha_on_login'] = 1 > $this->getLimit();;
		}
	}

	public function BeforeLogin()
	{
		if (0 >= $this->getLimit()) {
			$bResult = false;

			$HTTP = \SnappyMail\HTTP\Request::factory();

			$aPayload = array(
			    'private_key' => $this->Config()->Get('plugin', 'private_key', ''),
			    'response'    => $this->Manager()->Actions()->GetActionParam('DcaptchaResponse', '')
			);
			$sJsonData = \json_encode($aPayload);
			$aHeaders = array(
			    'Content-Type: application/json',
			    'Content-Length: ' . \strlen($sJsonData)
			);
			$oResponse = $HTTP->doRequest('POST', 'https://captcha.ddos-guard.net/siteverify', $sJsonData, $aHeaders);
			if ($oResponse) {
				$aResp = \json_decode($oResponse->body, true);
				if (\is_array($aResp) && isset($aResp['success']) && $aResp['success']) {
					$bResult = true;
				}
			}

			if (!$bResult) {
				$this->Manager()->Actions()->Logger()->Write('DecaptchaResponse:'.$sResult);
				throw new \RainLoop\Exceptions\ClientException(105);
			}
		}
	}

	/**
	 * @param string $sAction
	 * @param array $aResponse
	 */
	public function AfterLogin(array &$aResponse)
	{
		if (isset($aResponse['Result'])) {
			$oCacher = $this->Manager()->Actions()->Cacher();
			$iConfigLimit = (int) $this->Config()->Get('plugin', 'error_limit', 0);

			$sKey = $this->getCaptchaCacherKey();

			if (0 < $iConfigLimit && $oCacher && $oCacher->IsInited()) {
				if (false === $aResponse['success']) {
					$iLimit = 0;
					$sLimut = $oCacher->Get($sKey);
					if (\is_numeric($sLimut)) {
						$iLimit = (int) $sLimut;
					}

					$oCacher->Set($sKey, ++$iLimit);

					if ($iConfigLimit <= $iLimit) {
						$aResponse['Captcha'] = true;
					}
				} else {
					$oCacher->Delete($sKey);
				}
			}
		}
	}

	public function ContentSecurityPolicy(\SnappyMail\HTTP\CSP $CSP)
	{
		$CSP->add('script-src', 'https://captcha.ddos-guard.net/static/');
		$CSP->add('frame-src', 'https://captcha.ddos-guard.net/static/');
		$CSP->add('script-src', 'https://captcha.ddos-guard.net/siteverify/');
		$CSP->add('frame-src', 'https://captcha.ddos-guard.net/siteverify/');
		$CSP->add('connect-src', 'https://captcha.ddos-guard.net/reg/');
		$CSP->add('connect-src', 'https://captcha.ddos-guard.net/reg');
		$CSP->add('script-src', 'https://captcha.ddos-guard.net/reg');
		$CSP->add('frame-src', 'https://captcha.ddos-guard.net/reg');
		$CSP->add('connect-src', 'https://captcha.ddos-guard.net/payload');
		$CSP->add('script-src', 'https://captcha.ddos-guard.net/payload');
		$CSP->add('frame-src', 'https://captcha.ddos-guard.net/payload');
		$CSP->add('connect-src', 'https://captcha.ddos-guard.net/userverify');
		$CSP->add('script-src', 'https://captcha.ddos-guard.net/userverify');
		$CSP->add('frame-src', 'https://captcha.ddos-guard.net/userverify');
		$CSP->add('connect-src', 'https://captcha.ddos-guard.net wss://captcha.ddos-guard.net');
	}

}
