// Shodan Monitor - System Console "IP list" setting.
//
// Plain JavaScript (no JSX, no bundler): it uses the React instance that the
// Mattermost web app exposes as window.React.
(function () {
    'use strict';

    var PLUGIN_ID = 'shodan-monitor';
    var React = window.React;
    var h = React.createElement;

    function apiBase() {
        return (window.basename || '') + '/plugins/' + PLUGIN_ID + '/api/v1';
    }

    function csrfToken() {
        var m = document.cookie.match(/(?:^|;\s*)MMCSRF=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : '';
    }

    function request(method, path, body) {
        var headers = {'X-Requested-With': 'XMLHttpRequest'};
        if (method !== 'GET') {
            headers['X-CSRF-Token'] = csrfToken();
            headers['Content-Type'] = 'text/plain; charset=utf-8';
        }
        return fetch(apiBase() + path, {
            method: method,
            credentials: 'same-origin',
            headers: headers,
            body: body,
        }).then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t.trim() || ('HTTP ' + res.status));
                });
            }
            return res.json();
        });
    }

    function fmtDate(ms) {
        if (!ms) {
            return '';
        }
        return new Date(ms).toLocaleString();
    }

    function Summary(props) {
        var s = props.summary;
        if (!s) {
            return null;
        }
        var children = [];
        if (s.applied) {
            var parts = [s.added + ' added', s.removed + ' removed', s.unchanged + ' unchanged'];
            if (s.duplicates) {
                parts.push(s.duplicates + (s.duplicates === 1 ? ' duplicate line skipped' : ' duplicate lines skipped'));
            }
            children.push(h('div', {key: 'head'}, h('strong', null, 'List replaced - ' + s.total + ' IPs. '), parts.join(' · ')));
        } else {
            children.push(h('div', {key: 'head'}, h('strong', null, s.message)));
        }
        if (s.rejected_count) {
            children.push(h('div', {key: 'rh', style: {marginTop: 8}}, h('strong', null, 'Rejected lines (' + s.rejected_count + '):')));
            children.push(h('ul', {key: 'rl', style: {maxHeight: 220, overflowY: 'auto', margin: '4px 0 0 0', paddingLeft: 20}},
                (s.rejected || []).map(function (r) {
                    return h('li', {key: r.line}, 'line ' + r.line + ': ', h('code', null, r.value), ' - ' + r.reason);
                }),
                s.rejected_count > (s.rejected || []).length ?
                    h('li', {key: 'more'}, '... and ' + (s.rejected_count - s.rejected.length) + ' more') : null,
            ));
        }
        if (props.showWho && s.at) {
            children.push(h('div', {key: 'who', className: 'help-text', style: {marginTop: 6}},
                'Last upload: ' + fmtDate(s.at) + (s.by ? ' by @' + s.by : '') + (s.source ? ' (' + s.source + ')' : '')));
        }
        return h('div', {
            className: s.applied ? 'alert alert-success' : 'alert alert-warning',
            style: {marginTop: 12, marginBottom: 0},
        }, children);
    }

    function IPListSetting(props) {
        var _info = React.useState(null);
        var info = _info[0];
        var setInfo = _info[1];
        var _file = React.useState(null);
        var file = _file[0];
        var setFile = _file[1];
        var _busy = React.useState(false);
        var busy = _busy[0];
        var setBusy = _busy[1];
        var _result = React.useState(null);
        var result = _result[0];
        var setResult = _result[1];
        var _error = React.useState('');
        var error = _error[0];
        var setError = _error[1];
        var inputRef = React.useRef(null);

        function load() {
            request('GET', '/iplist').then(setInfo).catch(function (e) {
                setError('Could not load the IP list: ' + e.message);
            });
        }
        React.useEffect(load, []);

        function upload() {
            if (!file) {
                return;
            }
            setBusy(true);
            setError('');
            setResult(null);
            file.text().then(function (text) {
                return request('POST', '/iplist', text);
            }).then(function (res) {
                setResult(res.summary);
                setFile(null);
                if (inputRef.current) {
                    inputRef.current.value = '';
                }
                load();
            }).catch(function (e) {
                setError('Upload failed: ' + e.message);
            }).then(function () {
                setBusy(false);
            });
        }

        var count = info ? info.count : null;
        return h('div', {style: {maxWidth: 640}},
            h('div', {style: {marginBottom: 10}},
                count === null ? 'Loading...' : h('span', null, h('strong', null, count + (count === 1 ? ' IP' : ' IPs')), ' in the monitored list.'),
                count ? h('span', null, ' ', h('a', {href: apiBase() + '/iplist/download'}, 'Download current list')) : null,
                info && info.previous_size ? h('span', null, ' · ', h('a', {href: apiBase() + '/iplist/previous'}, 'Download previous list (' + info.previous_size + ')')) : null,
            ),
            // The native file input is hidden (the System Console styles hide its
            // button); a regular button opens the file picker instead.
            h('input', {
                ref: inputRef,
                type: 'file',
                accept: '.txt,text/plain',
                style: {display: 'none'},
                onChange: function (e) {
                    setFile(e.target.files && e.target.files[0] ? e.target.files[0] : null);
                    setResult(null);
                    setError('');
                },
            }),
            h('div', {style: {display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap'}},
                h('button', {
                    type: 'button',
                    className: 'btn btn-tertiary',
                    id: 'shodanMonitorChooseFile',
                    disabled: busy || props.disabled,
                    onClick: function () {
                        if (inputRef.current) {
                            inputRef.current.click();
                        }
                    },
                }, 'Choose file'),
                h('span', {
                    id: 'shodanMonitorFileName',
                    style: {opacity: file ? 1 : 0.64, overflowWrap: 'anywhere'},
                }, file ? file.name + ' (' + Math.max(1, Math.round(file.size / 1024)) + ' KB)' : 'No file selected'),
            ),
            h('div', {style: {marginTop: 10}},
                h('button', {
                    type: 'button',
                    className: 'btn btn-primary',
                    id: 'shodanMonitorUpload',
                    disabled: !file || busy || props.disabled,
                    onClick: upload,
                }, busy ? 'Uploading...' : (count ? 'Upload and replace list' : 'Upload list')),
            ),
            error ? h('div', {className: 'alert alert-danger', style: {marginTop: 12, marginBottom: 0}}, error) : null,
            result ? h(Summary, {summary: result}) : (info && info.last_upload ? h(Summary, {summary: info.last_upload, showWho: true}) : null),
        );
    }

    function Plugin() {}
    Plugin.prototype.initialize = function (registry) {
        if (typeof registry.registerAdminConsoleCustomSetting === 'function') {
            registry.registerAdminConsoleCustomSetting('IPList', IPListSetting, {showTitle: true});
        }
    };

    window.registerPlugin(PLUGIN_ID, new Plugin());
})();
