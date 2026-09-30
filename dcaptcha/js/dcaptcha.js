
(rl => {
	rl && addEventListener('rl-view-model', e => {
		const id = e.detail.viewModelTemplateID;
		if (e.detail && ('AdminLogin' === id || 'Login' === id) && rl.pluginSettingsGet('dcaptcha', 'show_captcha_on_login')) {
			let
				nId = null,
				script;

			const
				mode = 'Login' === id ? 'user' : 'admin',

				doc = document,

				container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),

				ShowDcaptcha = () => {
					if (window.ddgcaptcha && null === nId && container) {
						const oEl = doc.createElement('div');
						oEl.className = 'ddg-captcha-container';
						oEl.dataset.sitekey = rl.pluginSettingsGet('dcaptcha', 'public_key');
						oEl.dataset.callback = 'handleCapchaToken';
						container.after(oEl);

						nId = window.ddgcaptcha.render(oEl, {
							'sitekey': rl.pluginSettingsGet('dcaptcha', 'public_key'),
							'theme': rl.pluginSettingsGet('dcaptcha', 'theme')
						});
					}
				},

				StartDcaptcha = () => {
					if (window.ddgcaptcha) {
						ShowDcaptcha();
					} else if (!script) {
						script = doc.createElement('script');
						script.defer = true;
//						script.onload = ShowDcaptcha;
						script.src = 'https://captcha.ddos-guard.net/static/api.js?render=explicit&onload=ShowDcaptcha'
						doc.head.append(script);
					}
				};

			window.ShowDcaptcha = ShowDcaptcha;

			StartDcaptcha();

			addEventListener(`sm-${mode}-login`, e => {
				if (null !== nId && window.ddgcaptcha) {
					e.detail.set('DcaptchaResponse', window.ddgcaptcha.getResponse(nId));
				} else {
					e.preventDefault();
				}
			});

			addEventListener(`sm-${mode}-login-response`, e => {
				if (e.detail.error) {
					if (null !== nId && window.ddgcaptcha) {
						window.ddgcaptcha.reset(nId);
					} else if (e.detail.data && e.detail.data.Captcha) {
						StartDcaptcha();
					}
				}
			});
		}
	});

})(window.rl);
