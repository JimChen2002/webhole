import React, { Component } from 'react';
import {
  SafeTextarea,
  PromotionBar,
  HighlightedMarkdown,
  BrowserWarningBar,
} from './Common';
import { MessageViewer } from './Message';
import { LoginPopup } from './login';
import { ColorPicker } from './color_picker';
import { ConfigUI } from './Config';
import fixOrientation from 'fix-orientation';
import copy from 'copy-to-clipboard';
import { cache } from './cache';
import {
  // API_VERSION_PARAM,
  // THUHOLE_API_ROOT,
  // API,
  get_json,
  API_ROOT,
  API_VERSION_PARAM,
} from './flows_api';

import './UserAction.css';
import { UnregisterPopup } from './delete_account';

const BASE64_RATE = 4 / 3;
const MAX_IMG_DIAM = 8000;
const MAX_IMG_PX = 5000000;
const MAX_IMG_FILESIZE = 450000 * BASE64_RATE;

export const TokenCtx = React.createContext({
  value: null,
  set_value: () => {},
});

export function DoUpdate(clear_cache = true) {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then((registrations) => {
      for (let registration of registrations) {
        console.log('unregister', registration);
        registration.unregister();
      }
    });
  }
  if (clear_cache) cache().clear();
  setTimeout(() => {
    window.location.reload(true);
  }, 1000);
}

export function InfoSidebar(props) {
  return (
    <div>
      <PromotionBar />
      <BrowserWarningBar />
      <LoginForm show_sidebar={props.show_sidebar} />
      <div className="box list-menu">
        <a href={process.env.REACT_APP_RULES_URL} target="_blank">
          <span className="icon icon-textfile" />
          <label>Hole Rules</label>
        </a>
        &nbsp;&nbsp;
        <a href={process.env.REACT_APP_TOS_URL} target="_blank">
          <span className="icon icon-textfile" />
          <label>Service Terms</label>
        </a>
        &nbsp;&nbsp;
        <a href={process.env.REACT_APP_PRIVACY_URL} target="_blank">
          <span className="icon icon-textfile" />
          <label>Privacy Terms</label>
        </a>
        <br />
        &nbsp;&nbsp;
        <a href={process.env.REACT_APP_GITHUB_ISSUES_URL} target="_blank">
          <span className="icon icon-github" />
          <label>Feedback</label>
        </a>
        <br />
        <UnregisterPopup>
          {(do_popup) => (
            <a onClick={do_popup}>
              <span className="icon icon-refresh" />
              <label>Delete Account</label>
            </a>
          )}
        </UnregisterPopup>
      </div>
      {/*
        <div className="box help-desc-box">
          <p>
            <a onClick={DoUpdate}>??????????????????</a>
            ?????????????????????{process.env.REACT_APP_BUILD_INFO || '---'}{' '}
            {process.env.NODE_ENV}??? ????????????????????????????????????????????????????????????
          </p>
        </div>
      */}
      <div className="box help-desc-box">
        <p>Contact us: {process.env.REACT_APP_CONTACT_EMAIL}</p>
      </div>
    </div>
  );
}

export class LoginForm extends Component {
  // copy_token(token) {
  //   if (copy(token))
  //     alert(
  //       '???????????????\n??????????????????????????????????????????' +
  //         process.env.REACT_APP_WEBSITE_URL +
  //         '??????????????????????????????token???????????????????????????????????????',
  //     );
  // }

  render() {
    return (
      <TokenCtx.Consumer>
        {(token) => (
          <div>
            <div className="login-form box">
              {token.value ? (
                <div>
                  <p>
                    <b>???????????????</b>
                    <button
                      type="button"
                      onClick={() => {
                        fetch(
                          API_ROOT + 'security/logout?' + API_VERSION_PARAM(),
                          {
                            method: 'POST',
                            headers: {
                              TOKEN: token.value,
                            },
                          },
                        )
                          .then(get_json)
                          .then((json) => {
                            if (json.code !== 0) throw new Error(json.msg);
                            token.set_value(null);
                          })
                          .catch((err) => {
                            console.error(err);
                            alert('' + err);
                            token.set_value(null);
                          });
                      }}
                    >
                      <span className="icon icon-logout" /> ??????
                    </button>
                    <br />
                  </p>
                  <p>
                    <a
                      onClick={() => {
                        this.props.show_sidebar(
                          '????????????',
                          <MessageViewer token={token.value} />,
                        );
                      }}
                    >
                      ??????????????????
                    </a>
                    <br />
                    ??????????????????????????????????????????????????????????????????
                  </p>
                  {/*<p>*/}
                  {/*  <a onClick={this.copy_token.bind(this, token.value)}>*/}
                  {/*    ?????? User Token*/}
                  {/*  </a>*/}
                  {/*  <br />*/}
                  {/*  ?????? User Token*/}
                  {/*  ?????????????????????????????????????????????????????????????????????????????????????????????????????????Token???*/}
                  {/*</p>*/}
                </div>
              ) : (
                <LoginPopup token_callback={token.set_value}>
                  {(do_popup) => (
                    <div>
                      <p>
                        <button type="button" onClick={do_popup}>
                          <span className="icon icon-login" />
                          &nbsp;Log in
                        </button>
                      </p>
                      <p>
                        <small>
                          {process.env.REACT_APP_TITLE} provide service for CMU students only,
                          please verify your identity with CMU email
                        </small>
                      </p>
                    </div>
                  )}
                </LoginPopup>
              )}
            </div>
          </div>
        )}
      </TokenCtx.Consumer>
    );
  }
}

export class VoteEditBox extends Component {
  constructor(props) {
    super(props);
    this.onChangeCheckAndSend = this.checkAndSend.bind(this);
  }
  checkAndSend(order) {
    return (value) => {
      const { sendVoteData } = this.props;
      sendVoteData({ [order]: value });
    };
  }
  render() {
    let { num } = this.props;
    const inputPile = [];
    for (let i = 0; i < num; i += 1) {
      inputPile.push(
        <input
          key={i}
          maxLength="15"
          style={{ padding: '0 2px', margin: '2px 2px' }}
          onChange={(event) => {
            this.onChangeCheckAndSend(i + 1)(event.target.value);
          }}
          placeholder={i + 1}
        />,
      );
    }
    return (
      <div>
        <hr />
        <p>??????2~4???????????????????????????15??????</p>
        {inputPile}
      </div>
    );
  }
}

export class PostForm extends Component {
  constructor(props) {
    super(props);
    this.state = {
      text: '',
      loading_status: 'done',
      img_tip: null,
      preview: false,
      vote: false,
      voteOptionNum: 0,
      voteData: { 1: null, 2: null, 3: null, 4: null },
      tag: '????????????',
    };
    this.img_ref = React.createRef();
    this.area_ref = this.props.area_ref || React.createRef();
    this.on_change_bound = this.on_change.bind(this);
    this.on_img_change_bound = this.on_img_change.bind(this);
    this.global_keypress_handler_bound = this.global_keypress_handler.bind(
      this,
    );
    this.color_picker = new ColorPicker();
  }

  global_keypress_handler(e) {
    if (
      e.code === 'Enter' &&
      !e.ctrlKey &&
      !e.altKey &&
      ['input', 'textarea'].indexOf(e.target.tagName.toLowerCase()) === -1
    ) {
      if (this.area_ref.current) {
        e.preventDefault();
        this.area_ref.current.focus();
      }
    }
  }
  componentDidMount() {
    document.addEventListener('keypress', this.global_keypress_handler_bound);
  }
  componentWillUnmount() {
    document.removeEventListener(
      'keypress',
      this.global_keypress_handler_bound,
    );
  }

  on_change(value) {
    this.setState({
      text: value,
    });
  }

  do_post(text, img) {
    let data = new URLSearchParams();
    let path;
    if (this.props.action === 'docomment') {
      data.append('pid', this.props.pid);
      data.append('reply_to_cid', this.props.reply_to_ref.reply_to);
      path = 'send/comment?';
    } else {
      path = 'send/post?';
    }
    data.append('text', this.state.text);
    data.append('type', img ? 'image' : 'text');
    if (this.state.tag !== '????????????') {
      data.append('tag', this.state.tag);
    }
    if (img) data.append('data', img);
    // ??????
    if (this.state.vote) {
      let voteObj = this.state.voteData;
      Object.keys(voteObj).forEach((item) => {
        if (!voteObj[item]) delete voteObj[item];
      });
      let voteArray = Object.values(voteObj);
      voteArray.map((char) => {
        data.append('vote_options[]', char);
      });
    }

    // fetch??????
    fetch(API_ROOT + path + API_VERSION_PARAM(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        TOKEN: this.props.token,
      },
      body: data,
    })
      .then(get_json)
      .then((json) => {
        if (json.code !== 0) {
          if (json.msg) alert(json.msg);
          throw new Error(JSON.stringify(json));
        }
        this.setState({
          loading_status: 'done',
          text: '',
          preview: false,
        });
        this.area_ref.current.clear();
        this.props.on_complete();
      })
      .catch((e) => {
        console.error(e);
        alert('????????????');
        this.setState({
          loading_status: 'done',
        });
      });
  }

  proc_img(file) {
    return new Promise((resolve, reject) => {
      function return_url(url) {
        const idx = url.indexOf(';base64,');
        if (idx === -1) throw new Error('img not base64 encoded');

        return url.substr(idx + 8);
      }

      let reader = new FileReader();
      function on_got_img(url) {
        const image = new Image();
        image.onload = () => {
          let width = image.width;
          let height = image.height;
          let compressed = false;

          if (width > MAX_IMG_DIAM) {
            height = (height * MAX_IMG_DIAM) / width;
            width = MAX_IMG_DIAM;
            compressed = true;
          }
          if (height > MAX_IMG_DIAM) {
            width = (width * MAX_IMG_DIAM) / height;
            height = MAX_IMG_DIAM;
            compressed = true;
          }
          if (height * width > MAX_IMG_PX) {
            let rate = Math.sqrt((height * width) / MAX_IMG_PX);
            height /= rate;
            width /= rate;
            compressed = true;
          }
          console.log('chosen img size', width, height);

          let canvas = document.createElement('canvas');
          let ctx = canvas.getContext('2d');
          canvas.width = width;
          canvas.height = height;
          ctx.drawImage(image, 0, 0, width, height);

          let quality_l = 0.1,
            quality_r = 0.9,
            quality,
            new_url;
          while (quality_r - quality_l >= 0.03) {
            quality = (quality_r + quality_l) / 2;
            new_url = canvas.toDataURL('image/jpeg', quality);
            console.log(
              quality_l,
              quality_r,
              'trying quality',
              quality,
              'size',
              new_url.length,
            );
            if (new_url.length <= MAX_IMG_FILESIZE) quality_l = quality;
            else quality_r = quality;
          }
          if (quality_l >= 0.101) {
            console.log('chosen img quality', quality);
            resolve({
              img: return_url(new_url),
              quality: quality,
              width: Math.round(width),
              height: Math.round(height),
              compressed: compressed,
            });
          } else {
            reject('???????????????????????????');
          }
        };
        image.src = url;
      }
      reader.onload = (event) => {
        fixOrientation(event.target.result, {}, (fixed_dataurl) => {
          on_got_img(fixed_dataurl);
        });
      };
      reader.readAsDataURL(file);
    });
  }

  on_img_change() {
    if (this.img_ref.current && this.img_ref.current.files.length)
      this.setState(
        {
          img_tip: '??????????????????????????????',
        },
        () => {
          this.proc_img(this.img_ref.current.files[0])
            .then((d) => {
              this.setState({
                img_tip:
                  `???${d.compressed ? '?????????' : '??????'} ${d.width}*${
                    d.height
                  } / ` +
                  `?????? ${Math.floor(d.quality * 100)}% / ${Math.floor(
                    d.img.length / BASE64_RATE / 1000,
                  )}KB???`,
              });
            })
            .catch((e) => {
              this.setState({
                img_tip: `???????????????${e}`,
              });
            });
        },
      );
    else
      this.setState({
        img_tip: null,
      });
  }

  on_submit(event) {
    if (event) event.preventDefault();
    if (this.state.loading_status === 'loading') return;
    if (this.img_ref.current.files.length) {
      this.setState({
        loading_status: 'processing',
      });
      this.proc_img(this.img_ref.current.files[0])
        .then((d) => {
          this.setState({
            loading_status: 'loading',
          });
          this.do_post(this.state.text, d.img);
        })
        .catch((e) => {
          alert(e);
        });
    } else {
      this.setState({
        loading_status: 'loading',
      });
      this.do_post(this.state.text, null);
    }
  }

  toggle_preview() {
    this.setState({
      preview: !this.state.preview,
    });
  }

  addVote() {
    let { voteOptionNum } = this.state;
    if (voteOptionNum >= 4) {
      alert('????????????4?????????');
    } else if (voteOptionNum == 0) {
      voteOptionNum = 2;
    } else {
      voteOptionNum++;
    }
    this.setState({ voteOptionNum });
  }

  render() {
    const { vote } = this.state;
    let replyClassName =
      'reply-form box' + (this.state.text ? ' reply-sticky' : '');
    let tagsArrayAfter = process.env.REACT_APP_SENDABLE_TAGS.split(',');
    return (
      <form
        onSubmit={this.on_submit.bind(this)}
        className={
          this.props.action === 'dopost' ? 'post-form box' : replyClassName
        }
      >
        <div className="post-form-bar">
          <label>
            {/*<a>????????????</a>*/}
            <span className={'post-upload'}>
              <span className="icon icon-image" />
              &nbsp;????????????
            </span>
            <input
              ref={this.img_ref}
              type="file"
              accept="image/*"
              disabled={this.state.loading_status !== 'done'}
              onChange={this.on_img_change_bound}
            />
          </label>
          {/* ?????????????????????????????????????????????*/}
          {this.props.action === 'dopost' ? (
            !vote ? (
              <button
                type="button"
                onClick={() => {
                  this.setState({ vote: true, voteOptionNum: 2 });
                }}
              >
                <span className="icon icon-how_to_vote" />
                &nbsp;??????
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  this.addVote();
                }}
              >
                <span className="icon icon-how_to_vote" />
                &nbsp;??????
              </button>
            )
          ) : (
            <div></div>
          )}
          {this.state.preview ? (
            <button
              type="button"
              onClick={() => {
                this.toggle_preview();
              }}
            >
              <span className="icon icon-eye-blocked" />
              &nbsp;??????
            </button>
          ) : (
            <button
              type="button"
              onClick={() => {
                this.toggle_preview();
              }}
            >
              <span className="icon icon-eye" />
              &nbsp;??????
            </button>
          )}
          {this.state.loading_status !== 'done' ? (
            <button disabled="disabled">
              <span className="icon icon-loading" />
              &nbsp;
              {this.state.loading_status === 'processing' ? '??????' : '??????'}
            </button>
          ) : (
            <button type="submit">
              <span className="icon icon-send" />
              &nbsp;??????
            </button>
          )}
        </div>
        {!!this.state.img_tip && (
          <p className="post-form-img-tip">
            <a
              onClick={() => {
                this.img_ref.current.value = '';
                this.on_img_change();
              }}
            >
              ????????????
            </a>
            {this.state.img_tip}
          </p>
        )}
        {this.state.preview ? (
          <div
            className={
              this.props.action === 'dopost' ? 'post-preview' : 'reply-preview'
            }
          >
            <HighlightedMarkdown
              text={this.state.text}
              color_picker={this.color_picker}
              show_pid={() => {}}
            />
          </div>
        ) : (
          <SafeTextarea
            ref={this.area_ref}
            id={this.props.pid}
            on_change={this.on_change_bound}
            on_submit={this.on_submit.bind(this)}
          />
        )}
        {this.state.voteOptionNum !== 0 && (
          <VoteEditBox
            num={this.state.voteOptionNum}
            sendVoteData={(voteDataObj) => {
              let preVoteData = this.state.voteData;
              Object.assign(preVoteData, voteDataObj);
              this.setState({ voteData: preVoteData });
            }}
          />
        )}
        {this.props.action === 'dopost' && (
          <div>
            <small>
              ???????????????????????????
              <a href={process.env.REACT_APP_RULES_URL} target="_blank">
                ????????????
              </a>
              &nbsp;
              <span style={{ float: 'right' }}>
                <select
                  className="selectCss"
                  onChange={(e) => this.setState({ tag: e.target.value })}
                >
                  <option className="selectOption">????????????</option>
                  {tagsArrayAfter.map((tag, i) => (
                    <option className="selectOption" key={i} value={tag}>
                      #{tag}
                    </option>
                  ))}
                </select>
              </span>
            </small>
          </div>
        )}
      </form>
    );
  }
}
