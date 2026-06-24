// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require rpc';
'require ui';
'require dom';
'require view.netbird.dom-helpers as nb';

// 版本管理 Tab —— 三来源(NetBird-Release / NetBird-OpenWRT / 自定义下载链接)。
// 后端:get_binary_info(check_remote) / update_binary(url) / set_binary_source(source,version) / delete_custom_binary(version)。
//   - 进页只显本地信息(不联网);远端版本由「检测更新」按钮显式拉(避限流)。
//   - Release:检测更新后若有新版,「立即更新」按钮紧挨「检测更新」。
//   - OpenWRT:切换键非 active 即可点;无副本时后端非破坏性 opkg download 自动获取(免删 init.d)。
//   - 自定义:仅此选项显 URL 框 + 下载;下载按真二进制版本号存多版本,可切换/删除。架构由后端 ELF 头校验。
//   - 选中 active 来源不显示「此来源已生效」(隐藏切换键)。
//   - 纯操作按钮,无 Save&Apply / form.Map;binary_source 由 set_binary_source rpc 直写 UCI。
// 渲染全程 E()/dom-helpers(XSS 安全基线)。

var callBinaryInfo   = rpc.declare({ object: 'luci.netbird', method: 'get_binary_info',     params: ['check_remote'],      expect: {} });
var callStartUpdate = rpc.declare({ object: 'luci.netbird', method: 'start_binary_update', params: ['url', 'checksum'], expect: {} });
var callBinaryProgress = rpc.declare({ object: 'luci.netbird', method: 'get_binary_update_progress', params: [], expect: {} });
var callCancelUpdate = rpc.declare({ object: 'luci.netbird', method: 'cancel_binary_update', params: [], expect: {} });
var callSetSource    = rpc.declare({ object: 'luci.netbird', method: 'set_binary_source',    params: ['source', 'version'], expect: {} });
var callDeleteCustom = rpc.declare({ object: 'luci.netbird', method: 'delete_custom_binary', params: ['version'],           expect: {} });
var callLuciAppCheck = rpc.declare({ object: 'luci.netbird', method: 'check_luci_app_update', params: [], expect: {} });
var callLuciAppUpdate = rpc.declare({ object: 'luci.netbird', method: 'update_luci_app', params: [], expect: {} });

function fmtVer(v) { return (v && v.length) ? ('v' + v) : null; }

function srcLabel(src) {
	if (src === 'release') return 'NetBird-Release';
	if (src === 'opkg')    return 'NetBird-OpenWrt';
	if (src === 'custom')  return _('Custom download');
	return src || '';
}

return view.extend({
	// 纯操作按钮页:去掉标准 Save&Apply 页脚(各动作即时按钮 + 各自确认/反馈)。
	handleSaveApply: null,
	handleSave:      null,
	handleReset:     null,

	load: function () {
		// 进页只拉本地信息(不联网);远端由「检测更新」按钮触发。
		return L.resolveDefault(callBinaryInfo(false), { ok: false });
	},

	render: function (res) {
		var self = this;
		self._bin = (res && res.ok && res.data) ? res.data : {};
		self._sel = self._bin.active_source || 'release';   // 默认显示当前 active 来源
		self._relLatest = null;                             // checkUpdate(release) 结果缓存
		self._luciAppLatest = null;                         // checkLuciAppUpdate 结果缓存

		var container = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('NetBird') + ' — ' + _('Versions')),
			E('div', { 'class': 'cbi-map-descr' },
				_('The opkg package is the fallback baseline; the latest official build has more complete features.'))
		]);

		// ── 当前状态块 ───────────────────────────────────────────────────────
		self._statusBox = E('div', {});
		container.appendChild(self._statusBox);

		// ── 来源下拉(默认选中 active)─────────────────────────────────────────
		var mkOpt = function (v, label) {
			var attrs = { 'value': v };
			if (v === self._sel) attrs.selected = 'selected';
			return E('option', attrs, label);
		};
		var sel = E('select', {
			'class': 'cbi-input-select',
			'change': ui.createHandlerFn(self, 'onSelect')
		}, [
			mkOpt('release', 'NetBird-Release'),
			mkOpt('opkg', 'NetBird-OpenWrt'),
			mkOpt('custom', _('Custom download'))
		]);
		self._detailBox = E('div', {});

		container.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Binary source')),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Select source')),
				E('div', { 'class': 'cbi-value-field' }, [ sel ])
			]),
			self._detailBox
		]));

		self.renderStatus();
		self.renderDetail();

		return container;
	},

	renderStatus: function () {
		var d = this._bin || {};
		var lu = this._luciAppLatest || null;
		var luActs = [
			E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'checkLuciAppUpdate')
			}, _('Check for updates'))
		];
		if (lu && lu.update_available)
			luActs.push(E('button', {
				'class': 'btn cbi-button cbi-button-positive',
				'click': ui.createHandlerFn(this, 'confirmLuciAppUpdate')
			}, _('Update luci-app-netbird')));
		var luMsg = null;
		if (lu && lu.checking)
			luMsg = E('div', { 'class': 'cbi-value-description', 'style': 'color:#888' }, _('Checking…'));
		else if (lu && lu.error)
			luMsg = E('div', { 'class': 'cbi-value-description', 'style': 'color:#a00' }, lu.error);
		else if (lu && lu.latest_version && lu.update_available)
			luMsg = E('div', { 'class': 'cbi-value-description', 'style': 'color:#080' },
				_('luci-app-netbird update available: v%s').format(lu.latest_version));
		else if (lu && lu.latest_version)
			luMsg = E('div', { 'class': 'cbi-value-description', 'style': 'color:#080' },
				_('luci-app-netbird is already up to date (v%s).').format(lu.latest_version));
		var node = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Current')),
			E('div', { 'class': 'nb-conn-info' }, [
				E('div', { 'class': 'nb-pair' }, [
					E('span', { 'class': 'nb-pair-label' }, _('Active source')),
					E('span', { 'class': 'nb-pair-value' }, [
						nb.statusPill('connected', srcLabel(d.active_source || 'release'))
					])
				]),
				nb.pair(_('Running version'), fmtVer(d.running_version) || '-'),
				E('div', { 'class': 'nb-pair' }, [
					E('span', { 'class': 'nb-pair-label' }, _('luci-app-netbird')),
					E('div', { 'class': 'nb-pair-value nb-pair-value-block' }, [
						fmtVer(d.luci_app_version) || '-',
						' ',
						E('a', { 'href': 'https://github.com/dont-touchme/luci-app-netbird', 'target': '_blank', 'rel': 'noopener noreferrer' }, 'GitHub'),
						E('div', { 'class': 'cbi-section-actions', 'style': 'margin-top:.4em' }, this._spaced(luActs)),
						luMsg || E('span', {})
					])
				]),
				nb.pair(_('Architecture'), d.arch ? (d.arch + (d.uname_m ? (' (' + d.uname_m + ')') : '')) : '-')
			])
		]);
		dom.content(this._statusBox, node);
	},

	onSelect: function (ev) {
		this._sel = ev.target.value;
		this._relLatest = null;
		this.renderDetail();
	},

	// 切换按钮(active 来源返 null,不显示「此来源已生效」);非 active 显示「切换到此来源」(就绪才可点)。
	// 与其它操作按钮同进 cbi-section-actions,保持同一左对齐轴(布局修复)。
	switchButton: function (source, available) {
		var self = this, active = (self._bin || {}).active_source || 'release';
		if (source === active)
			return null;
		var btn = E('button', {
			'class': 'btn cbi-button cbi-button-positive',
			'click': ui.createHandlerFn(self, 'switchSource', source)
		}, _('Switch to this source'));
		if (!available)
			btn.disabled = true;
		return btn;
	},

	// 按钮间插空格(同一 cbi-section-actions 内多按钮)。
	_spaced: function (arr) {
		var out = [];
		for (var i = 0; i < arr.length; i++) {
			if (i) out.push(' ');
			out.push(arr[i]);
		}
		return out;
	},

	// LuCI rpc.js 只读取全局 L.env.rpctimeout,没有 per-call timeout。下载/切换二进制可能
	// 超过默认 20s,临时拉长,避免前端先报超时而后端稍后成功落盘。
	_withRpcTimeout: function (seconds, fn) {
		var had = Object.prototype.hasOwnProperty.call(L.env, 'rpctimeout');
		var old = L.env.rpctimeout;
		L.env.rpctimeout = Math.max(Number(old) || 20, seconds);

		return fn().then(function (res) {
			if (had) L.env.rpctimeout = old;
			else delete L.env.rpctimeout;
			return res;
		}, function (err) {
			if (had) L.env.rpctimeout = old;
			else delete L.env.rpctimeout;
			throw err;
		});
	},

	_fmtBytes: function (bytes) {
		var n = Math.max(0, Number(bytes) || 0);
		var units = ['B', 'KB', 'MB', 'GB'];
		var i = 0;
		while (n >= 1024 && i < units.length - 1) {
			n = n / 1024;
			i++;
		}
		return (i === 0 ? String(Math.round(n)) : n.toFixed(n >= 10 ? 1 : 2).replace(/\.0+$/, '')) + ' ' + units[i];
	},

	_fmtDownloadSpeed: function (bytesPerSecond) {
		var kb = Math.max(0, Number(bytesPerSecond) || 0) / 1024;
		return (kb >= 10 ? String(Math.round(kb)) : kb.toFixed(1).replace(/\.0$/, '')) + ' kb/s';
	},

	_fmtDuration: function (seconds) {
		var s = Math.max(0, Math.floor(Number(seconds) || 0));
		if (s < 60)
			return s + 's';
		var m = Math.floor(s / 60);
		s = s % 60;
		if (m < 60)
			return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
		var h = Math.floor(m / 60);
		m = m % 60;
		return h + 'h ' + (m < 10 ? '0' : '') + m + 'm';
	},

	_phaseText: function (phase) {
		if (phase === 'preparing' || phase === 'idle') return _('Preparing download...');
		if (phase === 'downloading') return _('Downloading...');
		if (phase === 'downloaded') return _('Download complete. Verifying...');
		if (phase === 'verifying') return _('Verifying checksum and architecture...');
		if (phase === 'extracting') return _('Extracting binary...');
		if (phase === 'installing') return _('Installing binary...');
		if (phase === 'stopping') return _('Stopping download...');
		if (phase === 'canceled') return _('Download stopped.');
		if (phase === 'done') return _('Binary installed.');
		if (phase === 'failed') return _('Download failed.');
		return _('Preparing download...');
	},

	_showDownloadModal: function () {
		var self = this;
		var bar = E('progress', { 'style': 'width:100%;max-width:38em;height:1.2em' });
		var status = E('p', { 'class': 'spinning' }, _('Preparing download...'));
		var downloaded = E('div', { 'class': 'cbi-value-description' }, _('Downloaded') + ': -');
		var speed = E('div', { 'class': 'cbi-value-description' }, _('Speed') + ': -');
		var elapsed = E('div', { 'class': 'cbi-value-description' }, _('Elapsed') + ': 0s');
		var stop = E('button', {
			'class': 'btn cbi-button cbi-button-negative',
			'click': ui.createHandlerFn(self, '_stopCurrentDownload')
		}, _('Stop download'));

		self._downloadNodes = {
			bar: bar,
			status: status,
			downloaded: downloaded,
			speed: speed,
			elapsed: elapsed,
			stop: stop
		};

		ui.showModal(_('Downloading NetBird binary'), [
			status,
			bar,
			E('div', { 'style': 'margin-top:.7em' }, [ downloaded, speed, elapsed ]),
			E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [ stop ])
		]);
		self._renderDownloadProgress({ phase: 'preparing', downloaded: 0, total: 0, speed: 0, elapsed: 0, active: true });
	},

	_renderDownloadProgress: function (p) {
		var n = this._downloadNodes;
		if (!n)
			return;
		p = p || {};
		var phase = p.phase || 'preparing';
		var downloaded = Math.max(0, Number(p.downloaded) || 0);
		var total = Math.max(0, Number(p.total) || 0);
		var speed = Math.max(0, Number(p.speed) || 0);
		var elapsed = Math.max(0, Number(p.elapsed) || 0);
		var active = !!p.active || phase === 'preparing' || phase === 'downloading' ||
			phase === 'verifying' || phase === 'extracting' || phase === 'installing' || phase === 'stopping';

		dom.content(n.status, this._phaseText(phase));
		if (phase === 'downloading')
			n.status.classList.add('spinning');
		else
			n.status.classList.remove('spinning');

		if (total > 0) {
			var pct = Math.min(100, Math.floor(downloaded * 100 / total));
			n.bar.setAttribute('max', String(total));
			n.bar.setAttribute('value', String(Math.min(downloaded, total)));
			dom.content(n.downloaded, _('Downloaded') + ': ' + this._fmtBytes(downloaded) + ' / ' + this._fmtBytes(total) + ' (' + pct + '%)');
		} else {
			n.bar.removeAttribute('value');
			n.bar.setAttribute('max', '100');
			dom.content(n.downloaded, _('Downloaded') + ': ' + this._fmtBytes(downloaded));
		}
		dom.content(n.speed, _('Speed') + ': ' + (speed > 0 ? this._fmtDownloadSpeed(speed) : '-'));
		dom.content(n.elapsed, _('Elapsed') + ': ' + this._fmtDuration(elapsed));

		n.stop.disabled = !active || phase === 'stopping';
		dom.content(n.stop, phase === 'stopping' ? _('Stopping...') : _('Stop download'));
	},

	_stopCurrentDownload: function () {
		var self = this;
		if (self._downloadStopping)
			return;
		self._downloadStopping = true;
		if (self._downloadNodes) {
			self._downloadNodes.stop.disabled = true;
			dom.content(self._downloadNodes.stop, _('Stopping...'));
		}
		return L.resolveDefault(callCancelUpdate(), { ok: false }).then(function (res) {
			if (res && res.ok)
				self._renderDownloadProgress(res.data || { phase: 'stopping' });
		});
	},

	_waitDownloadCompletion: function (token) {
		var self = this;
		return new Promise(function (resolve) {
			var poll = function () {
				if (self._downloadToken !== token) {
					resolve({ phase: 'canceled', message: '' });
					return;
				}
				L.resolveDefault(callBinaryProgress(), { ok: false }).then(function (res) {
					var p = (res && res.ok) ? (res.data || {}) : {};
					var phase = p.phase || 'idle';
					self._renderDownloadProgress(p);
					if (phase === 'done' || phase === 'failed' || phase === 'canceled') {
						resolve(p);
						return;
					}
					window.setTimeout(poll, 1000);
				});
			};
			poll();
		});
	},

	_downloadFailureMessage: function (res) {
		if (res && res.code === 'checksum_mismatch')
			return _('Checksum verification failed; the download was rejected.') + (res.message ? ' (' + res.message + ')' : '');
		if (res && res.code === 'insufficient_space')
			return _('Not enough storage space. Delete unused downloaded versions and try again.') + (res.message ? ' (' + res.message + ')' : '');
		if (res && res.code === 'download_canceled')
			return _('Download stopped.');
		if (res && res.message)
			return _(res.message);
		if (res && res.code)
			return res.code;
		return _('Download/install did not complete. Check the device logs and try again.');
	},

	renderDetail: function () {
		var self = this, d = self._bin || {}, sel = self._sel;
		var rows = [];

		if (sel === 'release') {
			var rel = d.release || {};
			rows.push(E('p', { 'class': 'cbi-section-descr' }, _('This is the official NetBird Release build.')));
			rows.push(nb.pair(_('Version'), rel.installed ? (fmtVer(rel.version) || '-') : _('Not installed')));
			rows.push(nb.pair(_('Path'), rel.path || '/usr/share/netbird/bin/netbird-release'));
			self._relCheck = E('div', { 'style': 'margin:.5em 0' });
			rows.push(self._relCheck);
			// 所有操作按钮同进一个 cbi-section-actions(左对齐):检测更新 +(有新版才)立即更新 +(非 active 才)切换。
			var acts = [
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(self, 'checkUpdate') }, _('Check for updates'))
			];
			if (self._relLatest && self._relLatest.update_available && self._relLatest.latest)
				acts.push(E('button', { 'class': 'btn cbi-button cbi-button-positive', 'click': ui.createHandlerFn(self, 'updateLatest') }, _('Update now (v%s)').format(self._relLatest.latest)));
			var sbR = self.switchButton('release', !!rel.installed);
			if (sbR) acts.push(sbR);
			rows.push(E('div', { 'class': 'cbi-section-actions' }, self._spaced(acts)));
		}
		else if (sel === 'opkg') {
			var op = d.opkg || {};
			rows.push(E('p', { 'class': 'cbi-section-descr' }, _('This is the OpenWrt package-repository build.')));
			rows.push(nb.pair(_('Version'), op.version ? (fmtVer(op.version) || '-') : _('Not installed / not in opkg database')));
			rows.push(nb.pair(_('Path'), op.path || '/usr/bin/netbird'));
			// 提示:无副本但 feed 可用 → 切换时自动获取;feed 也无 → 红字
			if (!op.copy_preserved && op.binary_available)
				rows.push(E('p', { 'class': 'cbi-section-descr' },
					_('No local opkg binary copy is kept; switching will fetch it from the opkg feed automatically (opkg download).')));
			else if (!op.binary_available)
				rows.push(E('p', { 'class': 'cbi-section-descr', 'style': 'color:#a00' },
					_('The opkg feed does not provide netbird on this device, so switching is unavailable. Check your package sources.')));
			self._opkgCheck = E('div', { 'style': 'margin:.5em 0' });
			rows.push(self._opkgCheck);
			var acts2 = [
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(self, 'checkUpdate') }, _('Check for updates'))
			];
			var sbO = self.switchButton('opkg', !!op.binary_available);
			if (sbO) acts2.push(sbO);
			rows.push(E('div', { 'class': 'cbi-section-actions' }, self._spaced(acts2)));
		}
		else {
			// 自定义下载链接:仅此选项显 URL 框 + 下载 + 已下载版本列表
			rows.push(E('p', { 'class': 'cbi-section-descr' }, _('Download the NetBird client from a custom URL, kept by version so you can roll back anytime.')));
			// 保留已输入的 URL 跨重渲染(URL 不持久化到 UCI 是有意设计,但同一会话内重渲染不该清空)。
			var prevUrl = (self._urlInput && self._urlInput.value) ? String(self._urlInput.value) : (d.release_url || '');
			self._urlInput = E('input', {
				'type': 'text', 'class': 'cbi-input-text', 'style': 'width:32em;max-width:90%',
				'placeholder': 'https://…/netbird_<ver>_linux_' + (d.arch || 'amd64') + '.tar.gz',
				'value': prevUrl
			});
			rows.push(E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Custom download URL')),
				E('div', { 'class': 'cbi-value-field' }, [
					self._urlInput,
					E('div', { 'class': 'cbi-value-description' },
						_('A NetBird tarball or a direct binary URL; after download it is checked against this CPU architecture.'))
				])
			]));
			// 可选校验和:填了就在执行前硬校验下载物(防 http:// 镜像被替换)。算法按长度自动判
			// (md5/sha1/sha256/sha512)。跨重渲染保留输入。
			var prevSha = (self._shaInput && self._shaInput.value) ? String(self._shaInput.value) : '';
			self._shaInput = E('input', {
				'type': 'text', 'class': 'cbi-input-text', 'style': 'width:32em;max-width:90%',
				'placeholder': _('optional — md5 / sha1 / sha256 / sha512 hex'),
				'value': prevSha
			});
			rows.push(E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Checksum (optional)')),
				E('div', { 'class': 'cbi-value-field' }, [
					self._shaInput,
					E('div', { 'class': 'cbi-value-description' },
						_('If set, the download must match this checksum or it is rejected. Use sha256 or stronger for tamper protection; md5/sha1 only guard against corruption.'))
				])
			]));
			rows.push(E('div', { 'class': 'cbi-section-actions' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(self, 'download') }, _('Download'))
			]));

			var cust = d.custom || {};
			var vers = cust.versions || [];
			rows.push(E('h4', { 'style': 'margin-top:1em' }, _('Downloaded versions')));
			if (!vers.length) {
				rows.push(E('p', { 'class': 'cbi-section-descr' }, _('No custom versions downloaded yet. Enter a URL above and click Download.')));
			} else {
				var list = [];
				for (var i = 0; i < vers.length; i++) {
					var v = vers[i];
					var acts;
					if (v.active) {
						acts = [ nb.statusPill('connected', _('In use')) ];
					} else {
						acts = [
							E('button', { 'class': 'btn cbi-button cbi-button-positive', 'click': ui.createHandlerFn(self, 'switchCustom', v.version) }, _('Switch to this version')),
							' ',
							E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(self, 'deleteCustom', v.version) }, _('Delete'))
						];
					}
					list.push(E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, fmtVer(v.version) || v.version),
						E('div', { 'class': 'cbi-value-field' }, acts)
					]));
				}
				rows.push(E('div', {}, list));
			}
		}

		dom.content(this._detailBox, E('div', {}, rows));
	},

	// 检测更新:get_binary_info(check_remote=true) → 刷新本地态 + 显示远端结果。
	checkUpdate: function () {
		var self = this;
		var which = self._sel;
		var target = (which === 'release') ? self._relCheck : self._opkgCheck;
		if (target) dom.content(target, E('em', { 'style': 'color:#888' }, _('Checking…')));
		return L.resolveDefault(callBinaryInfo(true), { ok: false }).then(function (res) {
			if (!(res && res.ok && res.data)) {
				ui.addNotification(null, E('p', {}, _('Check for updates failed.')), 'error');
				return;
			}
			self._bin = res.data;
			var d = res.data;
			if (which === 'release')
				self._relLatest = { latest: d.latest_version, update_available: d.update_available };
			self.renderStatus();
			self.renderDetail();   // 重建 detail(release 详情会据 _relLatest 显示「立即更新」)
			if (which === 'release') {
				var msg;
				if (!d.latest_version)
					msg = E('p', { 'style': 'color:#888' }, _('Could not reach GitHub to check the latest version.'));
				else if (d.update_available)
					msg = E('span', { 'style': 'color:#080' }, _('Latest official: v%s').format(d.latest_version));
				else
					msg = E('p', { 'style': 'color:#080' }, _('Already on the latest official version (v%s).').format(d.latest_version));
				if (self._relCheck) dom.content(self._relCheck, msg);
			} else {
				// 升级命令按系统包管理器分流(apk=OWRT25+ / opkg=24.10-);apk 机上「opkg upgrade」
				// 是不存在的命令,故用 d.pkg_mgr(后端 binary_info 暴露)给对应系统的命令。
				var upgradeCmd = (d.pkg_mgr === 'apk') ? 'apk upgrade netbird' : 'opkg upgrade netbird';
				var m2 = d.opkg_upgradable
					? E('p', { 'style': 'color:#080' }, _('Package upgrade available: v%s (run "%s").').format(d.opkg_upgradable, upgradeCmd))
					: E('p', { 'style': 'color:#888' }, _('No package upgrade found in the cached package lists.'));
				if (self._opkgCheck) dom.content(self._opkgCheck, m2);
			}
		});
	},

	checkLuciAppUpdate: function () {
		var self = this;
		self._luciAppLatest = { checking: true };
		self.renderStatus();
		return L.resolveDefault(callLuciAppCheck(), { ok: false }).then(function (res) {
			if (res && res.ok && res.data)
				self._luciAppLatest = res.data;
			else
				self._luciAppLatest = { error: (res && res.message) ? _(res.message) : _('Check for updates failed.') };
			self.renderStatus();
		});
	},

	confirmLuciAppUpdate: function () {
		var self = this;
		var info = self._luciAppLatest || {};
		ui.showModal(_('Update luci-app-netbird'), [
			E('p', {}, _('Update luci-app-netbird from v%s to v%s?').format(info.local_version || '-', info.latest_version || '?')),
			E('p', { 'class': 'cbi-section-descr' }, _('Packages will be downloaded from %s. The page may need to be reloaded after installation.').format(info.feed_url || '')),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button cbi-button-positive important', 'click': ui.createHandlerFn(self, 'updateLuciApp') }, _('Update luci-app-netbird'))
			])
		]);
	},

	updateLuciApp: function () {
		var self = this;
		ui.showModal(_('Updating luci-app-netbird'), [
			E('p', { 'class': 'spinning' }, _('Downloading and installing luci-app-netbird packages…'))
		]);
		return L.resolveDefault(self._withRpcTimeout(180, function () {
			return callLuciAppUpdate();
		}), { ok: false }).then(function (res) {
			ui.hideModal();
			if (res && res.ok) {
				ui.addNotification(null, E('p', {}, _('luci-app-netbird updated to v%s. Reload this page to use the new UI.').format((res.data && res.data.to) || '?')), 'info');
				self._luciAppLatest = null;
				return self.refresh();
			}
			ui.addNotification(null, E('p', {}, _('luci-app-netbird update failed: %s').format((res && res.message) || _('unknown error'))), 'error');
		}, function (err) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, _('luci-app-netbird update failed: %s').format(err && err.message ? err.message : _('unknown error'))), 'error');
		});
	},

	// 立即更新:从 GitHub 下载最新 release 写 netbird-release(空 url)。
	updateLatest: function () { return this._runUpdate(''); },

	// 自定义下载:读 URL + 可选 SHA-256 实时值;后端下载后 ELF 头硬校验,填了 SHA-256 则额外硬校验。
	download: function () {
		var self = this;
		var url = (self._urlInput && self._urlInput.value) ? String(self._urlInput.value).trim() : '';
		var sha = (self._shaInput && self._shaInput.value) ? String(self._shaInput.value).trim().toLowerCase() : '';
		if (!url) {
			ui.addNotification(null, E('p', {}, _('Enter a custom download URL first.')), 'warning');
			return;
		}
		if (sha && !/^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/.test(sha)) {
			ui.addNotification(null, E('p', {}, _('Enter a valid checksum: md5 (32), sha1 (40), sha256 (64) or sha512 (128) hex characters.')), 'warning');
			return;
		}
		// http:// 且未提供校验和:下载物会以 root 执行,镜像/中间人可替换 → 二次确认。
		if (/^http:\/\//i.test(url) && !sha) {
			ui.showModal(_('Insecure download'), [
				E('p', {}, _('This is a plain http:// URL with no checksum. The downloaded file is executed as root, so a malicious mirror or a man-in-the-middle could run arbitrary code. Prefer https://, or paste a checksum above.')),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
					E('button', { 'class': 'btn cbi-button cbi-button-negative important', 'click': ui.createHandlerFn(self, '_runUpdateConfirmed', url, sha) }, _('Download anyway'))
				])
			]);
			return;
		}
		return self._runUpdate(url, sha);
	},

	_runUpdateConfirmed: function (url, sha) { ui.hideModal(); return this._runUpdate(url, sha); },

	_runUpdate: function (url, sha) {
		var self = this;
		var token = (self._downloadToken || 0) + 1;
		self._downloadToken = token;
		self._downloadStopping = false;
		self._showDownloadModal();
		return L.resolveDefault(self._withRpcTimeout(30, function () {
			return callStartUpdate(url || '', sha || '');
		}), { ok: false }).then(function (res) {
			if (!(res && res.ok)) {
				self._downloadToken = token + 1;
				ui.hideModal();
				ui.addNotification(null, E('p', {}, _('Download/install failed: %s').format(self._downloadFailureMessage(res))), 'error');
				return;
			}
			return self._waitDownloadCompletion(token).then(function (progress) {
				self._downloadToken = token + 1;
				self._renderDownloadProgress(progress || {});
				ui.hideModal();
				var phase = progress && progress.phase;
				if (phase === 'done') {
					ui.addNotification(null, E('p', {}, _('Binary installed.')), 'info');
					return self.refresh();
				}
				if (phase === 'canceled') {
					ui.addNotification(null, E('p', {}, _('Download stopped.')), 'info');
					return self.refresh();
				}
				ui.addNotification(null, E('p', {}, _('Download/install failed: %s').format(
					self._downloadFailureMessage(progress && progress.message ? { message: progress.message } : null))), 'error');
				return self.refresh();
			});
		}, function (err) {
			self._downloadToken = token + 1;
			ui.hideModal();
			ui.addNotification(null, E('p', {}, _('Download/install failed: %s').format(err && err.message ? err.message : self._downloadFailureMessage(null))), 'error');
		});
	},

	switchSource: function (source) { return this._confirmSwitch(source, ''); },
	switchCustom: function (version) { return this._confirmSwitch('custom', version); },

	_confirmSwitch: function (source, version) {
		var self = this;
		var label = (source === 'custom') ? (srcLabel('custom') + ' v' + version) : srcLabel(source);
		var extra = (source === 'opkg')
			? E('p', { 'class': 'cbi-section-descr' }, _('If no local copy is kept, it will be fetched from the opkg feed first.'))
			: E('span', {});
		ui.showModal(_('Switch binary source'), [
			E('p', {}, _('Switch the active NetBird binary to %s? The NetBird service will restart briefly.').format(label)),
			extra,
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button cbi-button-positive', 'click': function () { self._doSwitch(source, version); } }, _('Switch source'))
			])
		]);
	},

	_doSwitch: function (source, version) {
		var self = this;
		ui.hideModal();
		ui.showModal(_('Switching binary source'), [
			E('p', { 'class': 'spinning' }, _('Switching and restarting NetBird…'))
		]);
		return L.resolveDefault(self._withRpcTimeout(180, function () {
			return callSetSource(source, version || '');
		}), { ok: false }).then(function (res) {
			ui.hideModal();
			if (res && res.ok)
				ui.addNotification(null, E('p', {}, _('Active source is now %s (running v%s).').format(srcLabel(source), (res.data && res.data.running_version) || '?')), 'info');
			else if (res && res.code === 'insufficient_space')
				ui.addNotification(null, E('p', {}, _('Not enough storage space. Delete unused downloaded versions and try again.') + (res.message ? ' (' + res.message + ')' : '')), 'error');
			else
				ui.addNotification(null, E('p', {}, (res && res.message) ? _(res.message) : _('Switch failed.')), 'error');
			return self.refresh();
		});
	},

	deleteCustom: function (version) {
		var self = this;
		ui.showModal(_('Delete version'), [
			E('p', {}, _('Delete downloaded custom version v%s? This only removes the stored binary file.').format(version)),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button cbi-button-negative important', 'click': function () { self._doDelete(version); } }, _('Delete'))
			])
		]);
	},

	_doDelete: function (version) {
		var self = this;
		ui.hideModal();
		return L.resolveDefault(callDeleteCustom(version), { ok: false }).then(function (res) {
			if (res && res.ok)
				ui.addNotification(null, E('p', {}, _('Deleted version v%s.').format(version)), 'info');
			else
				ui.addNotification(null, E('p', {}, (res && res.message) ? _(res.message) : _('Delete failed.')), 'error');
			return self.refresh();
		});
	},

	// 操作后刷新本地态(不联网);保持当前下拉选择。
	refresh: function () {
		var self = this;
		return L.resolveDefault(callBinaryInfo(false), { ok: false }).then(function (res) {
			self._bin = (res && res.ok && res.data) ? res.data : {};
			// 清陈旧「立即更新」缓存:更新/切换后版本已变,须重新「检测更新」才再显示(review MEDIUM)。
			self._relLatest = null;
			self.renderStatus();
			self.renderDetail();
		});
	}
});
