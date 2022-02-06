import React, { Component } from 'react';
import ReactDOM from 'react-dom';

import './login.css';
import './login_alt.css';

import { API_ROOT } from './old_infrastructure/const';
import { API_VERSION_PARAM, get_json } from './old_infrastructure/functions';

import {
  GoogleReCaptcha,
  GoogleReCaptchaProvider,
} from 'react-google-recaptcha-v3';
import ReCAPTCHA from 'react-google-recaptcha';

import UAParser from 'ua-parser-js';

const LOGIN_POPUP_ANCHOR_ID = 'pkuhelper_login_popup_anchor';

class LoginAltPopupSelf extends Component {
  constructor(props) {
    super(props);
    this.state = {
      loading_status: 'idle',
      recaptcha_verified: false,
      phase: 0,
      // excluded_scopes: [],
    };

    this.ref = {
      username: React.createRef(),
      andrew_email: React.createRef(),
      email_verification: React.createRef(),
      password: React.createRef(),
      password_confirm: React.createRef(),

      checkbox_terms: React.createRef(),
      checkbox_account: React.createRef(),
    };

    this.popup_anchor = document.getElementById(LOGIN_POPUP_ANCHOR_ID);
    if (!this.popup_anchor) {
      this.popup_anchor = document.createElement('div');
      this.popup_anchor.id = LOGIN_POPUP_ANCHOR_ID;
      document.body.appendChild(this.popup_anchor);
    }
  }

  next_step() {
    if (this.state.loading_status === 'loading') return;
    switch (this.state.phase) {
      case 0:
        this.do_login(this.props.token_callback);
        break;
      case 1:
        this.verify_email('v3', () => {});
        break;
      case 2:
        this.new_user_registration(this.props.token_callback);
        break;
      case 3:
        this.need_recaptcha();
        break;
    }
  }

  valid_registration() {
    if (
      !this.ref.checkbox_account.current.checked
    ) {
      alert('Please check to indicate your acknowledgement');
      return 1;
    }
    if (this.ref.password.current.value.length < 8) {
      alert('Password too short, should have length at least 8');
      return 2;
    }
    if (
      this.ref.password.current.value !==
      this.ref.password_confirm.current.value
    ) {
      alert('Passwords are not the same');
      return 3;
    }
    return 0;
  }

  async sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);

    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    return hashArray.map((b) => ('00' + b.toString(16)).slice(-2)).join('');
  }

  async hashpassword(password) {
    let password_hashed = await this.sha256(password);
    password_hashed = await this.sha256(password_hashed);
    return password_hashed;
  }

  verify_email(version, failed_callback) {
    const old_token = new URL(location.href).searchParams.get('old_token');
    const email = this.ref.andrew_email.current.value;
    const recaptcha_version = version;
    const recaptcha_token = localStorage['recaptcha'];
    // VALIDATE EMAIL IN FRONT-END HERE
    const body = new URLSearchParams();
    Object.entries({
      email,
      old_token,
      recaptcha_version,
      recaptcha_token,
    }).forEach((param) => body.append(...param));
    this.setState(
      {
        loading_status: 'loading',
      },
      () => {
        fetch(API_ROOT + 'security/login/check_email_invitation?' + API_VERSION_PARAM(), {
          method: 'POST',
          body,
        })
          .then((res) => res.json())
          .then((json) => {
            // COMMENT NEXT LINE
            //json.code = 2;
            if (json.code < 0) throw new Error(json.msg);
            this.setState({
              loading_status: 'done',
              phase: json.code,
            });
            if (json.code === 3) failed_callback();
          })
          .catch((e) => {
            alert('Fail to validate your email\n' + e);
            this.setState({
              loading_status: 'done',
            });
            console.error(e);
          });
      },
    );
  }

  async do_login(set_token) {
    const email = this.ref.username.current.value;
    const password = this.ref.password.current.value;
    let password_hashed = await this.hashpassword(password);
    const device_info = UAParser(navigator.userAgent).browser.name;
    const body = new URLSearchParams();
    Object.entries({
      email,
      password_hashed,
      device_type: 0,
      device_info,
    }).forEach((param) => body.append(...param));

    this.setState(
      {
        loading_status: 'loading',
      },
      () => {
        fetch(API_ROOT + 'security/login/login?' + API_VERSION_PARAM(), {
          method: 'POST',
          body,
        })
          .then(get_json)
          .then((json) => {
            if (json.code !== 0) {
              if (json.msg) throw new Error(json.msg);
              throw new Error(JSON.stringify(json));
            }

            set_token(json.token);
            alert('Login Successfully!');
            this.setState({
              loading_status: 'done',
            });
            this.props.on_close();
          })
          .catch((e) => {
            console.error(e);
            alert('Login Failed\n' + e);
            this.setState({
              loading_status: 'done',
            });
          });
      },
    );
  }

  async new_user_registration(set_token) {
    if (this.valid_registration() !== 0) return;
    const email = this.ref.username.current.value;
    const valid_code = this.ref.email_verification.current.value;
    const password = this.ref.password.current.value;
    let password_hashed = await this.hashpassword(password);
    const device_info = UAParser(navigator.userAgent).browser.name;
    const body = new URLSearchParams();
    Object.entries({
      email,
      password_hashed,
      device_type: 0,
      device_info,
      valid_code,
    }).forEach((param) => body.append(...param));
    this.setState(
      {
        loading_status: 'loading',
      },
      () => {
        fetch(
          API_ROOT + 'security/login/create_account_invitation?' + API_VERSION_PARAM(),
          {
            method: 'POST',
            body,
          },
        )
          .then(get_json)
          .then((json) => {
            if (json.code !== 0) {
              if (json.msg) throw new Error(json.msg);
              throw new Error(JSON.stringify(json));
            }

            set_token(json.token);
            alert('Login Successfully!');
            this.setState({
              loading_status: 'done',
            });
            this.props.on_close();
          })
          .catch((e) => {
            console.error(e);
            alert('Login Failed\n' + e);
            this.setState({
              loading_status: 'done',
            });
          });
      },
    );
  }

  need_recaptcha() {
    console.log(3);
  }

  render() {
    window.recaptchaOptions = {
      useRecaptchaNet: true,
    };
    return ReactDOM.createPortal(
      <GoogleReCaptchaProvider
        reCaptchaKey={process.env.REACT_APP_RECAPTCHA_V3_KEY}
        useRecaptchaNet={true}
      >
        <div>
          <div className="treehollow-login-popup-shadow" />
          <div className="treehollow-login-popup margin-popup">
            {this.state.phase === 0 && (
              <>
                <p>
                  <label>
                    Username:&nbsp;
                    <input
                      ref={this.ref.username}
                      type="text"
                      autoFocus={true}
                    />
                  </label>
                </p>
                <p>
                  <label>
                    Password:&nbsp;
                    <input
                      ref={this.ref.password}
                      type="password"
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          this.next_step();
                        }
                      }}
                    />
                  </label>
                </p>
                <p>
                  <a
                    onClick={() => {
                      alert(
                        'You can delete your account in the sidebar',
                      );
                    }}
                  >
                    Forget your password?
                  </a>
                </p>
                <p>
                  <button
                    onClick={()=>{
                      this.setState({
                        phase: 1,
                      })
                    }}
                  >
                    <b>Sign up</b>
                  </button>
                </p>
              </>
            )}
            {this.state.phase === 1 && (
              <>
                <p>
                  <b>Procedures:</b>
                </p>
                <p>
                  You will request an invitation code with your 
                  CMU email, and use it to sign up an anonymous account.
                </p>
                <p>
                  <b>Difference between invitation code and verification code:</b>
                </p>
                <p>
                  Invitation code is the same for everyone, so when signing up with 
                  it, you reveals nothing more than the fact that you have access 
                  to a CMU email.
                </p>
                <p>
                  <b>Best practice:</b>
                </p>
                <p>
                  1. After getting the code, you can wait some time.
                </p>
                <p>
                  2. You can get the code with a device, and then sign up with 
                  another device. We are compatible for both phone and computer.
                </p>
                <p>*Press continue if you have one*</p>
                <p>
                  <label>
                    Email&nbsp;
                    <input
                      ref={this.ref.andrew_email}
                      type="email"
                      autoFocus={true}
                    />
                  </label>
                  <p>
                    <button
                      onClick={()=>{
                        this.next_step()
                      }}
                    >
                      <b>Send code</b>
                    </button>
                  </p>
                </p>
              </>
            )}
            {(this.state.phase === 2) && (
              <>
                <p>
                  <b>Sign up</b>
                </p>
                <p>
                  <label>
                    Username&nbsp;
                    <input
                      ref={this.ref.username}
                      type="text"
                      autoFocus={true}
                    />
                  </label>
                </p>
                <p>
                  <label>
                    Invitation code&nbsp;
                    <input
                      ref={this.ref.email_verification}
                      type="text"
                    />
                  </label>
                </p>
                <p>
                  <label>
                    Password&nbsp;
                    <input ref={this.ref.password} type="password" />
                  </label>
                </p>
                <p>
                  <label>
                    Password&nbsp;
                    <input
                      ref={this.ref.password_confirm}
                      type="password"
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          this.next_step();
                        }
                      }}
                    />
                  </label>
                </p>
                <p>
                  <label>
                    <input type="checkbox" ref={this.ref.checkbox_account} />
                    I understand that I will not be able to get my account back if I forget my password.
                  </label>
                </p>
              </>
            )}
            {this.state.phase === 3 && (
              <>
                <p>
                  <b>Enter the invitation code {process.env.REACT_APP_TITLE}</b>
                </p>
                <RecaptchaV2Popup
                  callback={() => {
                    this.verify_email('v2', () => {
                      alert('reCAPTCHA风控系统校验失败');
                    });
                  }}
                >
                  {(do_popup) => (
                    <p>
                      {!this.state.recaptcha_verified && (
                        <GoogleReCaptcha
                          onVerify={(token) => {
                            this.setState({
                              recaptcha_verified: true,
                            });
                            console.log(token);
                            localStorage['recaptcha'] = token;
                            this.verify_email('v3', do_popup);
                          }}
                        />
                      )}
                    </p>
                  )}
                </RecaptchaV2Popup>
              </>
            )}
            <p>
              <button onClick={this.props.on_close}>Cancel</button>
              <button
                onClick={this.next_step.bind(this)}
                disabled={this.state.loading_status === 'loading'}
              >
                Continue
              </button>
            </p>
          </div>
        </div>
      </GoogleReCaptchaProvider>,
      this.popup_anchor,
    );
  }
}

export class LoginAltPopup extends Component {
  constructor(props) {
    super(props);
    this.state = {
      popup_show: false,
    };
    this.on_popup_bound = this.on_popup.bind(this);
    this.on_close_bound = this.on_close.bind(this);
  }

  on_popup() {
    this.setState({
      popup_show: true,
    });
  }

  on_close() {
    this.setState({
      popup_show: false,
    });
  }

  render() {
    return (
      <>
        {this.props.children(this.on_popup_bound)}
        {this.state.popup_show && (
          <LoginAltPopupSelf
            token_callback={this.props.token_callback}
            on_close={this.on_close_bound}
          />
        )}
      </>
    );
  }
}

export class RecaptchaV2Popup extends Component {
  constructor(props, context) {
    super(props, context);
    this.onChange = this.onChange.bind(this);
    this.state = {
      popup_show: false,
    };
    this.on_popup_bound = this.on_popup.bind(this);
    this.on_close_bound = this.on_close.bind(this);
  }

  on_popup() {
    this.setState({
      popup_show: true,
    });
  }

  on_close() {
    this.setState({
      popup_show: false,
    });
  }

  componentDidMount() {
    if (this.captchaRef) {
      console.log('started, just a second...');
      this.captchaRef.reset();
      this.captchaRef.execute();
    }
  }

  onChange(recaptchaToken) {
    localStorage['recaptcha'] = recaptchaToken;
    this.setState({
      popup_show: false,
    });
    this.props.callback();
  }

  render() {
    return (
      <>
        {this.props.children(this.on_popup_bound)}
        {this.state.popup_show && (
          <div>
            <div className="treehollow-login-popup-shadow" />
            <div className="treehollow-login-alt-popup">
              <div className="g-recaptcha">
                <ReCAPTCHA
                  ref={(el) => {
                    this.captchaRef = el;
                  }}
                  sitekey={process.env.REACT_APP_RECAPTCHA_V2_KEY}
                  // size={"compact"}
                  onChange={this.onChange}
                />
              </div>

              <p>
                <button onClick={this.on_close_bound}>取消</button>
              </p>
            </div>
          </div>
        )}
      </>
    );
  }
}
