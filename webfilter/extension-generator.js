function webFilterRules(config, gateway) {
  const rules = [];
  let id = 1;
  const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const condition = entry => ({
    regexFilter: '^https?://([^/]+\\.)?' + escape(entry.host) + '(?::[0-9]+)?/' + escape((entry.path || '').replace(/^\//, '')),
    resourceTypes: ['main_frame', 'sub_frame'],
  });
  const blocked = [...config.blockList, ...config.categoryRules.flatMap(category => category.websites)];
  for (const entry of blocked) rules.push({id: id++, priority: 1000,
    action: {type: 'redirect', redirect: {regexSubstitution: gateway + '#\\0'}}, condition: condition(entry)});
  for (const term of config.blockedUrlTerms || []) {
    const encoded = text => Array.from(new TextEncoder().encode(text), byte => '%' + byte.toString(16).padStart(2, '0')).join('');
    const variants = new Set([encodeURI(term), encodeURI(term.toUpperCase()), encoded(term), encoded(term.toUpperCase())].map(value => value.toLowerCase()));
    for (const value of variants) {
      if (value.length > 128) continue;
      rules.push({id: id++, priority: 1000, action: {type: 'redirect', redirect: {regexSubstitution: gateway + '#\\0'}},
        condition: {regexFilter: '^https?://.*' + escape(value) + '.*$', resourceTypes: ['main_frame', 'sub_frame']}});
    }
  }
  for (const entry of config.allowList) rules.push({id: id++, priority: 2000, action: {type: 'allow'}, condition: condition(entry)});
  rules.push({id: id++, priority: 4000, action: {type: 'allow'}, condition: {
    regexFilter: '^https://education\\.munetios\\.com/block(\\.html)?([?#]|$)', resourceTypes: ['main_frame', 'sub_frame'],
  }});
  if (config.enforceSafeMode) {
    // Keep safe-mode transforms in Chrome's URL matcher and blocks in its regex matcher.
    // A no-op redirect otherwise hides lower-priority blocks in the same matcher.
    const queryRule = (condition, key, value) => {
      rules.push({id: id++, priority: 5000,
        action: {type: 'redirect', redirect: {transform: {scheme: 'https', queryTransform: {addOrReplaceParams: [{key, value}]}}}},
        condition: {...condition,
          requestMethods: ['get'], resourceTypes: ['main_frame', 'sub_frame']},
      });
      const short = Array.from({length: value.length}, (_, index) => escape(value.slice(0, index)));
      const unsafe = [key + '(?:=(?:' + short.join('|') + '))?', key + '=' + escape(value) + '[^&#]+'];
      for (let index = 0; index < value.length; index++) {
        unsafe.push(key + '=' + escape(value.slice(0, index)) + '[^' + value[index] + '&#][^&#]*');
      }
      const {urlFilter, ...domains} = condition;
      for (const pattern of unsafe) {
        rules.push({id: id++, priority: 5001,
          action: {type: 'redirect', redirect: {transform: {scheme: 'https',
            queryTransform: {removeParams: [key], addOrReplaceParams: [{key, value}]}}}},
          condition: {...domains, regexFilter: '[?&]' + pattern + '(?:&|$)',
            isUrlFilterCaseSensitive: true, requestMethods: ['get'], resourceTypes: ['main_frame', 'sub_frame']},
        });
      }
    };
    queryRule({urlFilter: '|http', requestDomains: ['munetios.com'],
      excludedRequestDomains: ['education.munetios.com', 'api.munetios.com', 'accounts.munetios.com']}, 'schoolMode', 'true');
    const googleDomains = ('google.com google.ad google.ae google.com.af google.com.ag google.al google.am google.co.ao google.com.ar google.as google.at google.com.au google.az google.ba google.com.bd google.be google.bf google.bg google.com.bh google.bi google.bj google.com.bn google.com.bo google.com.br google.bs google.bt google.co.bw google.by google.com.bz google.ca google.cd google.cf google.cg google.ch google.ci google.co.ck google.cl google.cm google.cn google.com.co google.co.cr google.com.cu google.cv google.com.cy google.cz google.de google.dj google.dk google.dm google.com.do google.dz google.com.ec google.ee google.com.eg google.es google.com.et google.fi google.com.fj google.fm google.fr google.ga google.ge google.gg google.com.gh google.com.gi google.gl google.gm google.gr google.com.gt google.gy google.com.hk google.hn google.hr google.ht google.hu google.co.id google.ie google.co.il google.im google.co.in google.iq google.is google.it google.je google.com.jm google.jo google.co.jp google.co.ke google.com.kh google.ki google.kg google.co.kr google.com.kw google.kz google.la google.com.lb google.li google.lk google.co.ls google.lt google.lu google.lv google.com.ly google.co.ma google.md google.me google.mg google.mk google.ml google.com.mm google.mn google.com.mt google.mu google.mv google.mw google.com.mx google.com.my google.co.mz google.com.na google.com.ng google.com.ni google.ne google.nl google.no google.com.np google.nr google.nu google.co.nz google.com.om google.com.pa google.com.pe google.com.pg google.com.ph google.com.pk google.pl google.pn google.com.pr google.ps google.pt google.com.py google.com.qa google.ro google.ru google.rw google.com.sa google.com.sb google.sc google.se google.com.sg google.sh google.si google.sk google.com.sl google.sn google.so google.sm google.sr google.st google.com.sv google.td google.tg google.co.th google.com.tj google.tl google.tm google.tn google.to google.com.tr google.tt google.com.tw google.co.tz google.com.ua google.co.ug google.co.uk google.com.uy google.co.uz google.com.vc google.co.ve google.co.vi google.com.vn google.vu google.ws google.rs google.co.za google.co.zm google.co.zw google.cat').split(' ');
    queryRule({urlFilter: '|http', requestDomains: googleDomains,
      excludedRequestDomains: ['accounts.google.com']}, 'safe', 'active');
    queryRule({urlFilter: '|http', requestDomains: ['bing.com']}, 'adlt', 'strict');
    queryRule({urlFilter: '|http', requestDomains: ['duckduckgo.com']}, 'kp', '1');
    rules.push({id: id++, priority: 5000, action: {type: 'modifyHeaders', requestHeaders: [
      {header: 'YouTube-Restrict', operation: 'set', value: 'Strict'},
    ]}, condition: {requestDomains: ['youtube.com', 'youtube-nocookie.com', 'youtubei.googleapis.com'],
      resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'media', 'other']}});
  }
  return rules;
}

function webFilterTermMatch(value, terms = []) {
  const candidates = [value, value.replace(/\+/g, ' ')];
  for (let count = 0; count < 3; count++) {
    const decoded = candidates.at(-1).replace(/(?:%[0-9a-f]{2})+/gi, part => {
      try {return decodeURIComponent(part);} catch {return part;}
    });
    if (decoded === candidates.at(-1)) break;
    candidates.push(decoded);
  }
  return candidates.some(candidate => {
    const normalized = candidate.normalize('NFKC').toLowerCase();
    return terms.some(term => normalized.includes(term.normalize('NFKC').toLowerCase()));
  });
}

function webFilterBackground(makeRules, initializeCustomizer, matchesUrlTerm) {
  const base = fetch(chrome.runtime.getURL('config.json')).then(response => response.json());
  let current;
  let queue = Promise.resolve();
  const isBlockPage = value => {
    try { const url = new URL(value); return url.origin === 'https://education.munetios.com' && /^\/block(?:\.html)?$/.test(url.pathname); }
    catch { return false; }
  };
  async function refresh(resetBypasses) {
    const bundled = await base;
    const policy = await chrome.storage.managed.get(null);
    const next = {...bundled};
    for (const [key, field] of Object.entries({SchoolName: 'schoolName', ContactEmail: 'contactEmail', EnforceSafeMode: 'enforceSafeMode', AllowUserCss: 'allowUserCss', BlockList: 'blockList', BlockedUrlTerms: 'blockedUrlTerms', AllowList: 'allowList', BypassPassword: 'password'})) {
      if (Object.hasOwn(policy, key)) next[field] = policy[key];
    }
    next.allowUserCss = bundled.allowUserCss === true && next.allowUserCss === true;
    const rules = makeRules(next, chrome.runtime.getURL('block-gateway.html'));
    const old = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds: old.map(rule => rule.id), addRules: rules});
    if (resetBypasses) {
      const sessions = await chrome.declarativeNetRequest.getSessionRules();
      await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds: sessions.map(rule => rule.id)});
    }
    current = next;
    const name = next.schoolName + ' - Munetios WebFilter';
    await chrome.action.setTitle({title: name});
  }
  function scheduleRefresh(resetBypasses = false) {
    queue = queue.catch(() => {}).then(() => refresh(resetBypasses === true));
    queue.catch(error => console.error('WebFilter policy update failed', error));
    return queue;
  }
  scheduleRefresh();
  if (initializeCustomizer) initializeCustomizer(async () => { await queue; return current; });
  const navigationUpdates = new Map();
  async function enforceNavigation(details) {
    if (details.frameId !== 0 || !/^https?:/.test(details.url) || isBlockPage(details.url)) return;
    try {
      await queue;
      const config = current, original = new URL(details.url);
      const matches = entry => (original.hostname === entry.host || original.hostname.endsWith('.' + entry.host)) && (!entry.path || original.pathname.startsWith(entry.path));
      const sessions = await chrome.declarativeNetRequest.getSessionRules();
      const bypassed = sessions.some(rule => rule.condition.tabIds?.includes(details.tabId) && rule.condition.requestDomains?.some(host => original.hostname === host || original.hostname.endsWith('.' + host)));
      const allowed = bypassed || config.allowList.some(matches);
      const blocked = !allowed && (config.blockList.some(matches) || config.categoryRules.some(category => category.websites.some(matches)) || matchesUrlTerm(details.url, config.blockedUrlTerms));
      let target = new URL(original);
      if (blocked) {
        target = new URL('https://education.munetios.com/block');
        target.searchParams.set('url', original.href);
      } else if (config.enforceSafeMode) {
        const rules = makeRules(config, chrome.runtime.getURL('block-gateway.html'));
        for (const rule of rules) {
          const transform = rule.action.redirect?.transform;
          if (!transform) continue;
          const includes = domain => original.hostname === domain || original.hostname.endsWith('.' + domain);
          if (!rule.condition.requestDomains.some(includes) || rule.condition.excludedRequestDomains?.some(includes)) continue;
          target.protocol = 'https:';
          for (const param of transform.queryTransform.addOrReplaceParams) {
            const values = target.searchParams.getAll(param.key);
            if (values.length && values.every(value => value === param.value)) continue;
            target.searchParams.delete(param.key);
            target.searchParams.set(param.key, param.value);
          }
        }
      }
      if (target.href === original.href) return;
      const tab = await chrome.tabs.get(details.tabId);
      if (tab.url !== details.url || navigationUpdates.get(details.tabId) === target.href) return;
      navigationUpdates.set(details.tabId, target.href);
      try { await chrome.tabs.update(details.tabId, {url: target.href}); }
      finally {
        if (navigationUpdates.get(details.tabId) === target.href) navigationUpdates.delete(details.tabId);
      }
    } catch (error) { console.error('WebFilter navigation check failed', error); }
  }
  chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
    if (change.url || change.status === 'complete') enforceNavigation({tabId, frameId: 0, url: change.url || tab.url || ''});
  });
  chrome.storage.onChanged.addListener((changes, area) => { if (area === 'managed') scheduleRefresh(true); });
  chrome.runtime.onInstalled.addListener(scheduleRefresh);
  chrome.runtime.onStartup.addListener(scheduleRefresh);
  chrome.tabs.onRemoved.addListener(async tabId => {
    navigationUpdates.delete(tabId);
    attempts.delete(tabId);
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds: rules.filter(rule => rule.condition.tabIds?.includes(tabId)).map(rule => rule.id)});
  });
  const attempts = new Map();
  const inFlight = new Set();
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (!sender.tab || sender.frameId !== 0 || !isBlockPage(sender.url)) return;
    if (!['get-block-config', 'verify-bypass'].includes(message?.type)) return;
    (async () => {
      await queue;
      const config = current;
      if (message.type === 'get-block-config') {
        const value = new URL(sender.url).searchParams.get('url');
        let original;
        try { original = new URL(value); } catch {}
        const matches = entry => original && (original.hostname === entry.host || original.hostname.endsWith('.' + entry.host)) && (!entry.path || original.pathname.startsWith(entry.path));
        const category = config.categoryRules.find(item => item.websites.some(matches))?.name ||
          (value && matchesUrlTerm(value, config.blockedUrlTerms) ? config.strings.urlTermsCategory : config.strings.categoryFallback);
        respond({schoolName: config.schoolName, contactEmail: config.contactEmail, locale: config.locale, strings: config.strings, category});
        return;
      }
      const tabId = sender.tab.id;
      const original = new URL(new URL(sender.url).searchParams.get('url'));
      if (!['http:', 'https:'].includes(original.protocol) || typeof message.value !== 'string' || message.value.length > 128) throw new Error('Invalid bypass');
      if (inFlight.has(tabId)) { respond({success: false}); return; }
      const attempt = attempts.get(tabId) || {count: 0, after: 0};
      if (attempt.after > Date.now()) { respond({success: false}); return; }
      inFlight.add(tabId);
      try {
        const decode = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(message.value), 'PBKDF2', false, ['deriveBits']);
        const hash = new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: decode(config.password.salt), iterations: config.password.iterations}, key, 256));
        const expected = decode(config.password.hash);
        let difference = hash.length ^ expected.length;
        for (let i = 0; i < hash.length; i++) difference |= hash[i] ^ expected[i];
        if (difference) {
          attempt.count++;
          if (attempt.count >= 5) { attempt.after = Date.now() + 30000; attempt.count = 0; }
          attempts.set(tabId, attempt);
          respond({success: false});
          return;
        }
        attempts.delete(tabId);
        await queue;
        if (config !== current) throw new Error('Policy changed');
        const id = tabId + 1;
        const existing = (await chrome.declarativeNetRequest.getSessionRules()).find(rule => rule.id === id);
        const hosts = [...new Set([...(existing?.condition.requestDomains || []), original.hostname])];
        await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds: existing ? [id] : [], addRules: [{id, priority: 3000, action: {type: 'allow'}, condition: {
          tabIds: [tabId], requestDomains: hosts, resourceTypes: ['main_frame', 'sub_frame'],
        }}]});
        respond({success: true, url: original.href});
      } finally { inFlight.delete(tabId); }
    })().catch(() => respond({success: false}));
    return true;
  });
}

function webFilterGateway() {
  try {
    const original = new URL(location.hash.slice(1));
    if (!['http:', 'https:'].includes(original.protocol)) return;
    const target = new URL('https://education.munetios.com/block');
    target.searchParams.set('url', original.href);
    location.replace(target.href);
  } catch { document.body.textContent = 'Munetios WebFilter'; }
}

function webFilterBridge() {
  if (!/^\/block(?:\.html)?$/.test(location.pathname)) return;
  if (document.documentElement) document.documentElement.dataset.munetiosWebfilterBridge = 'ready';
  const original = new URLSearchParams(location.search).get('url') || '';
  let config;
  const byId = id => document.getElementById(id);
  const setText = (id, value) => { if (byId(id) && value) byId(id).textContent = value; };
  const error = id => {
    document.querySelector('.bypass-errors')?.classList.add('visible');
    document.querySelectorAll('.error-message').forEach(element => { element.style.display = element.id === id ? 'block' : 'none'; });
  };
  const apply = () => {
    if (!config) return;
    const name = config.schoolName + ' - Munetios WebFilter';
    document.documentElement.dataset.munetiosWebfilterBridge = 'ready';
    document.title = (config.strings.blockedPageTitle || 'This website has een blocked') + ' - ' + config.schoolName + ' - Munetios Webfilter';
    document.documentElement.lang = config.locale;
    setText('school-name', name);
    setText('website-url', original);
    setText('website-category', config.category || config.strings.categoryFallback);
    const fields = {'blocked-title': 'blockedTitle', 'blocked-description': 'blockedDescription', 'url-label': 'url', 'category-label': 'category', 'bypass-label': 'bypass', 'contact-label': 'contact', 'bypass-title': 'enterPassword', 'submit-label': 'submit', 'error-incorrect': 'incorrect', 'error-empty': 'empty', 'error-short': 'tooShort', 'error-invalid': 'invalid', 'error-extension': 'notExtension', 'error-failed': 'failed', 'bypass-note': 'temporary'};
    for (const [id, key] of Object.entries(fields)) setText(id, config.strings[key]);
    const input = byId('bypass-password-input');
    if (input) input.placeholder = config.strings.passwordPlaceholder;
  };
  chrome.runtime.sendMessage({type: 'get-block-config'}, response => {
    if (chrome.runtime.lastError || !response?.strings) return;
    config = response;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', apply, {once: true});
    else apply();
  });
  let pending = false;
  async function verify() {
    const input = byId('bypass-password-input');
    if (!input || pending) return;
    if (!input.value) { error('error-empty'); return; }
    pending = true;
    chrome.runtime.sendMessage({type: 'verify-bypass', value: input.value}, response => {
      pending = false;
      if (chrome.runtime.lastError) { error('error-failed'); return; }
      if (response?.success) { location.replace(response.url); return; }
      error('error-incorrect');
    });
  }
  window.addEventListener('click', event => {
    const button = event.target.closest?.('#bypass-button, #submit-bypass-button, #contact-button');
    if (!button) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (button.id === 'submit-bypass-button') { verify(); return; }
    if (button.id === 'contact-button') {
      if (config) location.href = 'mailto:' + encodeURIComponent(config.contactEmail) + '?subject=' + encodeURIComponent(config.strings.contact) + '&body=' + encodeURIComponent(original);
      return;
    }
    const panel = document.querySelector('.bypass-password');
    if (!panel) return;
    const visible = !panel.classList.contains('visible');
    panel.classList.toggle('visible', visible);
    panel.classList.toggle('hidden', !visible);
    if (visible) byId('bypass-password-input')?.focus();
  }, true);
  window.addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.target.id === 'bypass-password-input') {
      event.preventDefault(); event.stopImmediatePropagation(); verify();
    }
  }, true);
}

const webFilterManagedSchema = {
  type: 'object',
  properties: {
    SchoolName: {type: 'string', title: 'School name'},
    ContactEmail: {type: 'string', title: 'Administrator email'},
    EnforceSafeMode: {type: 'boolean', title: 'Enforce safe mode'},
    AllowUserCss: {type: 'boolean', title: 'Allow students to customize websites with CSS'},
    BlockList: {type: 'array', items: {type: 'object', properties: {host: {type: 'string'}, path: {type: 'string'}}, required: ['host']}},
    BlockedUrlTerms: {type: 'array', items: {type: 'string', minLength: 1}, title: 'Blocked text terms in URLs'},
    AllowList: {type: 'array', items: {type: 'object', properties: {host: {type: 'string'}, path: {type: 'string'}}, required: ['host']}},
    BypassPassword: {type: 'object', properties: {salt: {type: 'string'}, hash: {type: 'string'}, iterations: {type: 'integer', minimum: 210000}}, required: ['salt', 'hash', 'iterations']},
  },
};

function webFilterDeploymentGuide(config, deploymentHelp, safeModeHelp) {
  return [
    '# ' + config.schoolName + ' - Munetios WebFilter', deploymentHelp, safeModeHelp,
    '## Generate URL for Google Admin and ChromeOS',
    'Enter an HTTPS hosting folder and the extension version in the generator. For an existing deployment, select its saved signing key; otherwise Generate URL creates a new key. Generate URL produces a signed CRX3 package, an update XML file, the signing-key-derived extension ID and the ExtensionInstallForcelist pattern ID;UPDATE_XML_URL. Download the hosting ZIP and the signing key separately.',
    'Upload webfilter.crx and update.xml from the hosting ZIP to the chosen folder. The generated URLs do not work until the files are uploaded. Add the displayed extension ID in Google Admin, choose From a custom URL, paste the displayed update URL and select Force install for the school organizational unit. google-admin-deployment.json records the exact values; managed-policy.json is the extension policy configuration. ChromeOS devices must be managed by your organization. This generator does not modify policies or host files.',
    'Keep the signing key private, outside the extension and hosting folders. Import that same key and increase the extension version for subsequent Generate URL runs. A different key creates a different extension ID.',
    '## Local installation without a store',
    'Extract the ZIP into a permanent folder. In a dedicated Chromium or Chrome for Testing profile, open chrome://extensions, enable Developer mode, choose Load unpacked, and select the folder containing manifest.json. No store account or publication is needed. Reload the extension after replacing its files. Local unpacked installation is for manual installation/testing and does not force installation on other devices.',
    '## Self-hosted managed installation',
    '1. Choose an HTTPS URL on your own server for the update XML, and add that URL as update_url in manifest.json before packing the extension.',
    '2. Pack the extension as a signed CRX using Chromium or Chrome for Testing developer tools. Keep the signing private key securely outside the extension folder and reuse it for every update so the extension ID remains stable. Do not upload the private key. Use the extension ID associated with that signing key, not an unrelated unpacked directory ID.',
    '3. Run create-update-manifest.ps1 with the signed extension ID and the HTTPS URL where you will host the CRX. Upload the signed CRX and the resulting update.xml to your server at their configured URLs. Serve the CRX with application/x-chrome-extension and XML with application/xml.',
    '4. Google Admin: Devices > Chrome > Apps & extensions > Users & browsers. Select the school organizational unit, add a custom extension using its ID and your update XML URL, and select Force install. Upload managed-policy.json as its JSON policy configuration. Use an enrollment/platform combination that supports self-hosted force installation.',
    '5. Windows/Linux policy files: run create-chrome-policy.ps1 with the signed extension ID and your HTTPS update XML URL. It generates chrome-policy.json and chrome-policy.reg only. Review and deploy through your organization’s device management tools. Merge force-install entries with existing entries before deployment.',
    '6. On managed test devices, open chrome://policy, reload policies, and verify ExtensionInstallForcelist and extension settings. Confirm administrator installation at chrome://extensions. Test blocked URLs, bypass and each safe-mode provider.',
    'Chrome Web Store publication is optional. Self-hosted force installation still requires a signed CRX, a reachable update XML endpoint and supported browser/device management. A ZIP or unpacked directory is not a force-install endpoint. Stock Chrome restricts off-store installation on Windows and macOS to supported enterprise-managed deployments; a generated ZIP cannot remove that browser restriction.',
    '## Managed configuration',
    'managed-schema.json defines SchoolName, ContactEmail, EnforceSafeMode, AllowUserCss, BlockList, BlockedUrlTerms, AllowList and BypassPassword. Managed values override config.json. Removing a policy restores its bundled value. URL lists contain host and optional path objects; BlockedUrlTerms contains plain text strings. Category changes require an extension package update.',
    'Blocked URL terms match text anywhere in an address without regard to case, including domain, path, query and fragment. Encoded addresses are also checked during navigation. Terms use literal substring matching, not regular expressions. Allowlisted websites and valid temporary password bypasses retain their existing priority. Matching addresses use the same hosted restricted page.',
    'BypassPassword stores salt, hash and iterations, using PBKDF2-SHA-256 with 256 bits. Never put plaintext passwords in policy. Policy changes clear temporary bypasses. Otherwise bypasses last until their tab closes, including service worker suspension. Safe mode stays active for allowed and bypassed sites.',
    'Managed SchoolName changes the block page and toolbar title. The installed extension name comes from manifest.json; renaming it requires a package update.',
    '## Optional student CSS customization',
    'When AllowUserCss is included and enabled in the generated package, the toolbar popup provides an initially blank CSS editor, Apply CSS, Reset CSS and a DOM element picker. Applied CSS is stored locally by website origin and reapplied on later visits. Drafts and picked selectors are stored only for the browser session. Students reopen the popup after choosing an element to edit its selector rule. Custom CSS does not change filtering or bypass access controls.',
    'Managed AllowUserCss=false disables the editor and removes applied styles. This policy can only enable customization in a package originally generated with the feature enabled. Browser-internal pages, extension pages and the hosted WebFilter block page cannot be customized. Content scripts become available on a website after its next page load following extension installation.',
    'The wide CSS popup and element-picker banner use the Google Sans Flex font bundled at fonts/googlesansflex.ttf. The picker loads its font bytes through the extension instead of contacting a remote font server.',
    '## Hosted page',
    'Serve this project’s existing block.html and block.js at https://education.munetios.com/block, using a server rewrite if needed. Preserve the existing element IDs. The url query parameter contains the percent-encoded full blocked URL. The extension supplies branding, translations, administrator contact and password verification. Password hashes are never sent to the hosted page. The education.munetios.com host can see blocked URLs in its query/access logs.',
    'The bridge also supports /block.html. The hosted page must be deployed separately; generating this ZIP does not update that server.',
    '## Coverage',
    'Safe mode requests provider filtering, which cannot guarantee every result is safe. Other sites follow category and URL rules. Sites without a safe-mode interface need site-specific support. Chrome ForceGoogleSafeSearch and ForceYouTubeRestrict policies provide additional managed-browser coverage; the policy script includes them when safe mode is enabled. They are independent browser policies, so disable them separately if you later turn off safe mode.',
    'https://support.google.com/chrome/a/answer/6306504',
    'https://developer.chrome.com/docs/extensions/reference/manifest/storage',
    'https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux',
    'https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users',
  ].join('\n\n');
}

function webFilterPolicyScript(config) {
  const managed = {SchoolName: config.schoolName, ContactEmail: config.contactEmail,
    EnforceSafeMode: config.enforceSafeMode, AllowUserCss: config.allowUserCss, BlockList: config.blockList,
    BlockedUrlTerms: config.blockedUrlTerms || [], AllowList: config.allowList, BypassPassword: config.password};
  const bytes = new TextEncoder().encode(JSON.stringify(managed));
  const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
  return [
    'param(',
    "  [Parameter(Mandatory = $true)][ValidatePattern('^[a-p]{32}$')][string]$ExtensionId,",
    "  [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$UpdateUrl,",
    '  [string]$OutputDirectory = $PSScriptRoot',
    ')',
    "$ErrorActionPreference = 'Stop'",
    "$managed = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "')) | ConvertFrom-Json",
    "$entry = $ExtensionId + ';' + $UpdateUrl",
    "$policies = @{ ExtensionInstallForcelist = @($entry); '3rdparty' = @{ extensions = @{} } }",
    "$policies['3rdparty'].extensions[$ExtensionId] = @{ policy = $managed }",
    'if ($managed.EnforceSafeMode) { $policies.ForceGoogleSafeSearch = $true; $policies.ForceYouTubeRestrict = 2 }',
    'New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null',
    '$utf8 = New-Object Text.UTF8Encoding($false)',
    "[IO.File]::WriteAllText((Join-Path $OutputDirectory 'chrome-policy.json'), ($policies | ConvertTo-Json -Depth 20), $utf8)",
    "function Quote-Reg([string]$value) { return '\"' + $value.Replace('\\', '\\\\').Replace('\"', '\\\"').Replace([string][char]13, '\\r').Replace([string][char]10, '\\n') + '\"' }",
    "$lines = @('Windows Registry Editor Version 5.00', '', '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist]', ('\"1\"=' + (Quote-Reg $entry)), '', ('[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\' + $ExtensionId + '\\policy]'))",
    'foreach ($property in $managed.PSObject.Properties) {',
    '  $value = $property.Value',
    "  if ($value -is [bool]) { $regValue = if ($value) { 'dword:00000001' } else { 'dword:00000000' } }",
    '  elseif ($value -is [string]) { $regValue = Quote-Reg $value }',
    '  else { $regValue = Quote-Reg (ConvertTo-Json -InputObject $value -Depth 20 -Compress) }',
    "  $lines += (Quote-Reg $property.Name) + '=' + $regValue",
    '}',
    "if ($managed.EnforceSafeMode) { $lines += @('', '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]', '\"ForceGoogleSafeSearch\"=dword:00000001', '\"ForceYouTubeRestrict\"=dword:00000002') }",
    "[IO.File]::WriteAllLines((Join-Path $OutputDirectory 'chrome-policy.reg'), $lines, [Text.Encoding]::Unicode)",
    "Write-Output ('Policy files written to ' + $OutputDirectory)",
  ].join('\r\n');
}

function webFilterUpdateManifestScript(version) {
  return [
    'param(',
    "  [Parameter(Mandatory = $true)][ValidatePattern('^[a-p]{32}$')][string]$ExtensionId,",
    "  [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$CrxUrl,",
    '  [string]$OutputDirectory = $PSScriptRoot',
    ')',
    "$ErrorActionPreference = 'Stop'",
    'New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null',
    '$settings = New-Object System.Xml.XmlWriterSettings',
    '$settings.Indent = $true',
    '$settings.Encoding = New-Object Text.UTF8Encoding($false)',
    "$writer = [Xml.XmlWriter]::Create((Join-Path $OutputDirectory 'update.xml'), $settings)",
    'try {',
    '  $writer.WriteStartDocument()',
    "  $writer.WriteStartElement('gupdate', 'http://www.google.com/update2/response')",
    "  $writer.WriteAttributeString('protocol', '2.0')",
    "  $writer.WriteStartElement('app')",
    "  $writer.WriteAttributeString('appid', $ExtensionId)",
    "  $writer.WriteStartElement('updatecheck')",
    "  $writer.WriteAttributeString('codebase', $CrxUrl)",
    "  $writer.WriteAttributeString('version', '" + version + "')",
    '  $writer.WriteEndElement()',
    '  $writer.WriteEndElement()',
    '  $writer.WriteEndElement()',
    '  $writer.WriteEndDocument()',
    '} finally { $writer.Dispose() }',
    "Write-Output ('Update manifest written to ' + (Join-Path $OutputDirectory 'update.xml'))",
  ].join('\r\n');
}
